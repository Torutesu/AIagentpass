import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  EXACT_CI_LANES,
  assertGithubCiRun,
  assertSourceBinding,
  assertCloudSignerKmsQualified,
  assertPlatformAuthQualified,
  assertTerminalResults,
  assertBrowserE2eEvidence,
  assertGithubArtifacts,
  scanReleaseArtifacts,
  scanProtectedArtifacts,
  assertGithubCommit,
  assertGithubWorkflowEvidence,
  assertExternalQualificationEvidence
} from "./ci-preflight.mjs";
import {
  PLATFORM_AUTH_SCENARIO_CHECKS,
  platformAuthScenarioEvidenceSHA256
} from "../qualification/platform-auth.mjs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const SHA = "a".repeat(40);
const TREE = "b".repeat(40);
const EXTERNAL_QUALIFICATION_SCHEMA = JSON.parse(fs.readFileSync(path.resolve("docs/qualification/external-qualification-evidence.schema.json"), "utf8"));
const EXTERNAL_QUALIFICATION_CONTRACT = fs.readFileSync(path.resolve("docs/qualification/external-qualification-contract.md"), "utf8");
const EXTERNAL_QUALIFICATION_RUNBOOK = fs.readFileSync(path.resolve("docs/qualification/external-qualification-runbook.md"), "utf8");
const jobs = (runId = "42", runAttempt = "3") => EXACT_CI_LANES.map((lane, index) => ({ name: lane, conclusion: "success", status: "completed", head_sha: SHA, run_id: runId, run_attempt: runAttempt, id: String(index + 1) }));

const ciRun = {
  id: 42,
  run_attempt: 3,
  workflow_id: 900,
  name: "CI",
  path: ".github/workflows/ci.yml",
  status: "completed",
  conclusion: "success",
  event: "push",
  head_branch: "main",
  head_sha: SHA,
  repository: { id: 700, full_name: "Torutesu/AIagentpass" },
  head_repository: { id: 700, full_name: "Torutesu/AIagentpass" }
};

const kmsEvidence = (sourceCommit = SHA) => ({
  schema_version: 1,
  kind: "agentpass-cloud-signer-kms-qualification",
  status: "passed",
  qualified: true,
  reason: null,
  source_commit: sourceCommit,
  source_tree: TREE,
  deployment_digest: "c".repeat(64),
  run_id: "42",
  job_id: "1001",
  started_at: "2026-08-20T00:00:00.000Z",
  completed_at: "2026-08-20T00:01:00.000Z",
  purpose_bindings: [],
  iam_matrix: [],
  scenarios: [],
  postgres: { status: "passed", instances: [] }
});
const platformEvidence = () => ({
  schema_version: 1,
  kind: "agentpass-platform-auth-qualification",
  status: "passed",
  qualified: true,
  reason: null,
  source_commit: SHA,
  source_tree: TREE,
  run_id: "42",
  job_id: "1002",
  started_at: "2026-08-20T00:00:00.000Z",
  completed_at: "2026-08-20T00:01:00.000Z",
  deployment_digests: { primary: "1".repeat(64), secondary: "2".repeat(64) },
  instances: ["primary", "secondary"].map((name, instanceIndex) => ({
    name,
    source_commit: SHA,
    deployment_digest: String(instanceIndex + 1).repeat(64),
    scenarios: ["static_config", "mtls_peer_binding", "workload_identity_binding", "webauthn_consumption", "http_contract", "rotation", "resilience"].map((scenario, index) => {
      if (!["rotation", "resilience"].includes(scenario)) {
        return { scenario, status: "passed", evidence_sha256: String(index + instanceIndex + 2).repeat(64).slice(0, 64) };
      }
      const evidence = {
        schema_version: 1,
        kind: "agentpass-platform-auth-qualification-scenario",
        scenario,
        status: "passed",
        instance: name,
        source_commit: SHA,
        source_tree: TREE,
        deployment_digest: String(instanceIndex + 1).repeat(64),
        run_id: "42",
        job_id: "1002",
        started_at: "2026-08-20T00:00:00.000Z",
        completed_at: "2026-08-20T00:01:00.000Z",
        checks: PLATFORM_AUTH_SCENARIO_CHECKS[scenario].map((check_id) => ({
          check_id,
          status: "passed",
          expected: { type: "boolean", value: true },
          result: { type: "boolean", value: true }
        }))
      };
      return { scenario, status: "passed", evidence, evidence_sha256: platformAuthScenarioEvidenceSHA256(evidence) };
    })
  }))
});

const externalCheck = (checkId, status = "passed") => ({
  check_id: checkId,
  status,
  expected: { type: "boolean", value: true },
  observed: { type: "boolean", value: status === "passed" },
  evidence_sha256: "d".repeat(64)
});

const externalExecution = (kind) => ({
  kind: "external_runner",
  real_execution: true,
  runner_id: `runner-${kind}`,
  run_id: "42",
  job_id: "1001",
  run_attempt: "3",
  source_commit: SHA,
  source_tree: TREE,
  artifact_sha256: "e".repeat(64),
  started_at: "2026-08-20T00:00:00.000Z",
  completed_at: "2026-08-20T00:01:00.000Z",
  environment: { kind, identity: `${kind}-qualification` }
});

const EXTERNAL_REQUIRED_CHECKS = {
  github_actions: ["canonical_push_run", "exact_six_lanes", "source_sha_binding", "artifact_inventory_binding"],
  postgresql: ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"],
  managed_kms: ["provider_identity", "key_version_binding", "iam_matrix", "rotation_disable", "response_loss_reconciliation", "canary_sign_verify"],
  webauthn: ["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"],
  macos_hardware: ["apple_silicon_signed_notarized", "intel_t2_signed_notarized", "secure_enclave_identity", "negative_identity_entitlement", "lifecycle_recovery"]
};
const externalGate = (kind, status = "passed") => status === "not_run"
  ? { status, qualified: false, reason: "external_runner_unavailable", execution: null, required_checks: EXTERNAL_REQUIRED_CHECKS[kind], checks: [] }
  : { status, qualified: status === "passed", reason: status === "passed" ? null : "gate_failed", execution: externalExecution(kind), required_checks: EXTERNAL_REQUIRED_CHECKS[kind], checks: EXTERNAL_REQUIRED_CHECKS[kind].map((checkId) => externalCheck(checkId, status)) };

const externalEvidence = (status = "passed") => ({
  schema_version: 1,
  kind: "agentpass-external-qualification",
  status,
  qualified: status === "passed",
  reason: status === "passed" ? null : status === "not_run" ? "external_runner_unavailable" : "gate_failed",
  release: { repository: "Torutesu/AIagentpass", source_commit: SHA, source_tree: TREE, artifact_sha256: "f".repeat(64), ci_run_id: "42", ci_run_attempt: "3" },
  gates: {
    github_actions: externalGate("github_actions", status === "failed" ? "failed" : status === "not_run" ? "not_run" : "passed"),
    postgresql: externalGate("postgresql"),
    kms: externalGate("managed_kms"),
    webauthn: externalGate("webauthn"),
    macos_hardware: externalGate("macos_hardware")
  }
});

test("requires passed, qualified, source-bound KMS evidence for release promotion", () => {
  assert.throws(() => assertCloudSignerKmsQualified({ ...kmsEvidence(), status: "not_run", qualified: false, reason: "provider_not_configured" }, { expectedSourceCommit: SHA }));
  assert.throws(() => assertCloudSignerKmsQualified(kmsEvidence("c".repeat(40)), { expectedSourceCommit: SHA }));
  assert.throws(() => assertCloudSignerKmsQualified(kmsEvidence(), { expectedSourceCommit: "invalid" }));
});

test("requires passed, qualified, source-bound Platform auth evidence for release promotion", () => {
  const notRun = { schema_version: 1, kind: "agentpass-platform-auth-qualification", status: "not_run", qualified: false, reason: "provider_not_configured", started_at: "2026-08-20T00:00:00.000Z", completed_at: "2026-08-20T00:00:00.000Z" };
  assert.throws(() => assertPlatformAuthQualified(notRun, { expectedSourceCommit: SHA }));
  assert.throws(() => assertPlatformAuthQualified(notRun, { expectedSourceCommit: "invalid" }));
});

test("requires the complete Platform Auth source/tree/deployment/run/job binding", () => {
  const evidence = platformEvidence();
  const expectedDeploymentDigests = { primary: "1".repeat(64), secondary: "2".repeat(64) };
  assert.equal(assertPlatformAuthQualified(evidence, {
    expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedDeploymentDigests, expectedRunId: "42", expectedJobId: "1002"
  }).status, "passed");
  assert.throws(() => assertPlatformAuthQualified(evidence, {
    expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedDeploymentDigests: { ...expectedDeploymentDigests, secondary: "3".repeat(64) }, expectedRunId: "42", expectedJobId: "1002"
  }));
  assert.throws(() => assertPlatformAuthQualified(evidence, { expectedSourceCommit: SHA }));
});

test("external qualification contract is strict and never treats local or not-run evidence as passed", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(EXTERNAL_QUALIFICATION_SCHEMA);
  const valid = externalEvidence();
  assert.equal(validate(valid), true, JSON.stringify(validate.errors));
  assert.deepEqual(Object.keys(valid.gates).sort(), ["github_actions", "kms", "macos_hardware", "postgresql", "webauthn"]);
  const independentlyBound = (value) => Object.values(value.gates).every((gate) => gate.execution === null
    || (gate.execution.source_commit === value.release.source_commit
      && gate.execution.source_tree === value.release.source_tree
      && gate.execution.run_id === value.release.ci_run_id
      && gate.execution.run_attempt === value.release.ci_run_attempt));
  const notRun = structuredClone(valid);
  notRun.gates.postgresql = { status: "not_run", qualified: false, reason: "external_runner_unavailable", execution: null, required_checks: EXTERNAL_REQUIRED_CHECKS.postgresql, checks: [] };
  notRun.status = "not_run";
  notRun.qualified = false;
  notRun.reason = "external_runner_unavailable";
  assert.equal(validate(notRun), true, JSON.stringify(validate.errors));
  assert.equal(notRun.qualified, false);

  for (const mutate of [
    (value) => { value.gates.kms.qualified = false; },
    (value) => { value.gates.kms.checks[0].status = "failed"; },
    (value) => { value.gates.webauthn.execution.kind = "static"; },
    (value) => { value.gates.macos_hardware.status = "not_run"; },
    (value) => { value.gates.github_actions.extra = true; },
    (value) => { delete value.gates.postgresql; },
    (value) => { value.status = "passed"; value.qualified = true; value.reason = null; value.gates.kms.status = "not_run"; value.gates.kms.qualified = false; value.gates.kms.reason = "external_runner_unavailable"; value.gates.kms.execution = null; value.gates.kms.checks = []; },
    (value) => { value.status = "failed"; value.qualified = false; value.reason = "gate_failed"; value.gates.kms.status = "failed"; value.gates.kms.qualified = false; value.gates.kms.reason = "gate_failed"; value.gates.kms.checks[0].status = "passed"; },
    (value) => { value.gates.postgresql.execution.source_commit = "c".repeat(40); }
  ]) {
    const candidate = structuredClone(valid);
    mutate(candidate);
    assert.equal(validate(candidate) && independentlyBound(candidate), false, JSON.stringify(validate.errors));
  }
});

test("external qualification rejects passed checks whose matching observation is negative or not-run", () => {
  for (const mutate of [
    (check) => { check.expected = { type: "boolean", value: false }; check.observed = { type: "boolean", value: false }; },
    (check) => { check.expected = { type: "string", value: "not_run" }; check.observed = { type: "string", value: "not_run" }; },
    (check) => { check.expected = { type: "string", value: "simulated" }; check.observed = { type: "string", value: "simulated" }; }
  ]) {
    const candidate = structuredClone(externalEvidence());
    const expectedGateArtifacts = {};
    const expectedGateJobIds = {};
    Object.entries(candidate.gates).forEach(([name, gate], index) => {
      gate.execution.artifact_sha256 = String(index + 1).repeat(64);
      gate.execution.job_id = String(2001 + index);
      expectedGateArtifacts[name] = gate.execution.artifact_sha256;
      expectedGateJobIds[name] = gate.execution.job_id;
    });
    const binding = {
      expectedRepository: "Torutesu/AIagentpass",
      expectedSourceCommit: SHA,
      expectedSourceTree: TREE,
      expectedReleaseArtifactSha256: "f".repeat(64),
      expectedCiRunId: "42",
      expectedCiRunAttempt: "3",
      expectedGateArtifacts,
      expectedGateJobIds
    };
    assertExternalQualificationEvidence(candidate, binding);
    const check = candidate.gates.kms.checks[0];
    mutate(check);
    assert.throws(() => assertExternalQualificationEvidence(candidate, binding));
  }
});

test("external qualification contract documents all real-environment gates and the static-only boundary", () => {
  for (const [gate, contractPattern, runbookPattern] of [
    ["github_actions", /`github_actions`/u, /GitHub Actions/u],
    ["postgresql", /`postgresql`/u, /PostgreSQL 16 and 17/u],
    ["kms", /`kms`/u, /KMS\/HSM/u],
    ["webauthn", /`webauthn`/u, /WebAuthn/u],
    ["macos_hardware", /`macos_hardware`/u, /macOS lanes/u]
  ]) {
    assert.match(EXTERNAL_QUALIFICATION_CONTRACT, contractPattern, `missing contract gate ${gate}`);
    assert.match(EXTERNAL_QUALIFICATION_RUNBOOK, runbookPattern, `missing runbook gate ${gate}`);
  }
  assert.match(EXTERNAL_QUALIFICATION_CONTRACT, /not a degraded pass/u);
  assert.match(EXTERNAL_QUALIFICATION_CONTRACT, /local test suite.*must never manufacture/isu);
  assert.match(EXTERNAL_QUALIFICATION_RUNBOOK, /Do not replace a missing execution with a fixture/u);
  assert.match(EXTERNAL_QUALIFICATION_RUNBOOK, /static tests.*not an external qualification result/isu);
});

test("accepts exactly the six canonical passing lanes bound to one run and SHA", () => {
  const result = assertTerminalResults(jobs().reverse().map((job) => ({
    lane: job.name,
    terminal_result: "passed",
    head_sha: SHA,
    run_id: "42",
    job_id: job.id,
    run_attempt: "3",
    job_status: "completed",
    job_conclusion: "success",
    repository: "Torutesu/AIagentpass",
    workflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" }
  })), { expectedSha: SHA, expectedRunId: "42", expectedRunAttempt: "3", expectedRepository: "Torutesu/AIagentpass", expectedWorkflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" } });
  assert.equal(result.length, 6);
  assert.deepEqual(result.map((item) => item.lane), EXACT_CI_LANES);
});

test("requires one exact run attempt and real completed/successful terminal state for every CI lane", () => {
  const base = jobs().map((job) => ({
    lane: job.name,
    terminal_result: "passed",
    head_sha: SHA,
    run_id: "42",
    job_id: job.id,
    run_attempt: "3",
    job_status: "completed",
    job_conclusion: "success",
    repository: "Torutesu/AIagentpass",
    workflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" }
  }));
  for (const mutate of [
    (items) => { delete items[0].run_attempt; },
    (items) => { items[1].run_attempt = "4"; },
    (items) => { delete items[0].job_status; },
    (items) => { items[0].job_status = "in_progress"; },
    (items) => { delete items[0].job_conclusion; },
    (items) => { items[0].job_conclusion = "failure"; },
    (items) => { delete items[0].repository; },
    (items) => { delete items[0].workflow; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertTerminalResults(candidate, { expectedSha: SHA, expectedRunId: "42", expectedRunAttempt: "3", expectedRepository: "Torutesu/AIagentpass", expectedWorkflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" } }));
  }
});

test("browser E2E evidence is complete, source/run bound, and never accepts not_run or partial execution", () => {
  const raw = {
    schema_version: 1,
    kind: "agentpass-browser-e2e-result",
    phase: "tests",
    status: "passed",
    qualified: true,
    reason: null,
    executed: 54,
    expected: 54,
    exit_code: 0
  };
  const evidence = assertBrowserE2eEvidence(raw, {
    expectedSourceCommit: SHA,
    expectedSourceTree: TREE,
    expectedRunId: "42",
    expectedRunAttempt: "3",
    expectedJobId: "browser-e2e",
    expectedTests: 54
  });
  assert.equal(evidence.source_commit, SHA);
  assert.equal(evidence.source_tree, TREE);
  assert.equal(evidence.ci_run_id, "42");
  assert.equal(evidence.ci_run_attempt, "3");
  assert.equal(evidence.ci_job_id, "browser-e2e");
  assert.match(evidence.artifact_sha256, /^[0-9a-f]{64}$/u);
  for (const mutate of [
    (value) => { value.phase = "startup"; value.status = "not_run"; value.qualified = false; value.reason = "sandbox_eperm"; value.executed = 0; },
    (value) => { value.executed = 52; },
    (value) => { value.expected = 55; },
    (value) => { value.exit_code = 2; },
    (value) => { value.extra = "not-bound"; }
  ]) {
    const candidate = structuredClone(raw);
    mutate(candidate);
    assert.throws(() => assertBrowserE2eEvidence(candidate, {
      expectedSourceCommit: SHA,
      expectedSourceTree: TREE,
      expectedRunId: "42",
      expectedRunAttempt: "3",
      expectedJobId: "browser-e2e",
      expectedTests: 54
    }));
  }
  assert.throws(() => assertBrowserE2eEvidence(raw, {
    expectedSourceCommit: "not-a-sha", expectedSourceTree: TREE, expectedRunId: "42", expectedRunAttempt: "3", expectedJobId: "browser-e2e", expectedTests: 54
  }));
  assert.throws(() => assertBrowserE2eEvidence(raw, {
    expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedRunId: "42", expectedRunAttempt: "3", expectedJobId: "browser-e2e", expectedTests: 53
  }));
});

test("rejects missing, duplicate, extra, failed, not_proven, and mismatched lanes", () => {
  const base = jobs().map((job) => ({
    lane: job.name,
    terminal_result: "passed",
    head_sha: SHA,
    run_id: "42",
    job_id: job.id,
    run_attempt: "3",
    job_status: "completed",
    job_conclusion: "success",
    repository: "Torutesu/AIagentpass",
    workflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" }
  }));
  for (const mutate of [
    (items) => items.pop(),
    (items) => { items[1].lane = items[0].lane; },
    (items) => { items[0].lane = "unknown"; },
    (items) => { items[0].terminal_result = "failed"; },
    (items) => { items[0].terminal_result = "not_proven"; },
    (items) => { items[0].head_sha = "c".repeat(40); },
    (items) => { items[0].run_id = "43"; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertTerminalResults(candidate, { expectedSha: SHA, expectedRunId: "42", expectedRunAttempt: "3", expectedRepository: "Torutesu/AIagentpass", expectedWorkflow: { id: "900", name: "CI", path: ".github/workflows/ci.yml" } }));
  }
});

test("requires a successful canonical push run and per-job source binding", () => {
  const run = ciRun;
  assert.equal(assertGithubCiRun(run, jobs(), { expectedSha: SHA, repository: "Torutesu/AIagentpass" }).terminal_results.length, 6);
  assert.equal(assertGithubCiRun(run, jobs(), { expectedSha: SHA, repository: "Torutesu/AIagentpass", expectedRunId: "42" }).run_id, "42");
  assert.throws(() => assertGithubCiRun(run, jobs(), { expectedSha: SHA, repository: "Torutesu/AIagentpass", expectedRunId: "43" }));
  assert.throws(() => assertGithubCiRun({ ...run, event: "pull_request" }, jobs(), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun({ ...run, head_branch: "codex/agent-platform" }, jobs(), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map((job) => ({ ...job, head_sha: "c".repeat(40) })), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map((job, index) => index === 0 ? { ...job, run_id: 43 } : job), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map((job, index) => index === 0 ? { ...job, name: "postgres-authority-16 extra" } : job), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map(({ run_id, ...job }) => job), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map((job, index) => index === 0 ? { ...job, id: jobs()[1].id } : job), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun(run, jobs().map((job, index) => index === 0 ? { ...job, status: "in_progress" } : job), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun({ ...run, run_attempt: 4 }, jobs(), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun({ ...run, workflow_id: "not-a-workflow-id" }, jobs(), { expectedSha: SHA }));
  assert.throws(() => assertGithubCiRun({ ...run, head_repository: undefined }, jobs(), { expectedSha: SHA, repository: "Torutesu/AIagentpass" }));
});

test("binds workflow jobs and artifact digests to repository, workflow, source, attempt, and terminal state", () => {
  const run = { ...ciRun, name: "Release candidate", path: ".github/workflows/release-candidate.yml", event: "workflow_dispatch" };
  const runJobs = [
    { id: 11, name: "verify-source", run_id: 42, run_attempt: 3, head_sha: SHA, status: "completed", conclusion: "success", workflow_name: "Release candidate" },
    { id: 12, name: "signed-candidate", run_id: 42, run_attempt: 3, head_sha: SHA, status: "completed", conclusion: "success", workflow_name: "Release candidate" }
  ];
  const artifacts = {
    total_count: 2,
    artifacts: ["notarized-release-candidate", "release-integrity-evidence"].map((name, index) => ({
      id: 100 + index,
      name,
      expired: false,
      digest: `sha256:${String(index + 1).repeat(64)}`,
      workflow_run: { id: 42, repository_id: 700, head_repository_id: 700, workflow_id: 900, head_branch: "main", head_sha: SHA, event: "workflow_dispatch", status: "completed", conclusion: "success", run_attempt: 3 }
    }))
  };
  const evidence = assertGithubWorkflowEvidence(run, { total_count: 2, jobs: runJobs }, artifacts, {
    repository: "Torutesu/AIagentpass", workflowName: "Release candidate", workflowPath: ".github/workflows/release-candidate.yml", expectedEvent: "workflow_dispatch", expectedRunId: "42", expectedSha: SHA,
    expectedJobNames: ["verify-source", "signed-candidate"], expectedArtifactNames: ["notarized-release-candidate", "release-integrity-evidence"]
  });
  assert.equal(evidence.run_attempt, "3");
  assert.equal(evidence.artifacts[0].digest, `sha256:${"1".repeat(64)}`);
  assert.throws(() => assertGithubWorkflowEvidence(run, { total_count: 2, jobs: runJobs.map((job) => ({ ...job, run_attempt: 4 })) }, artifacts, {
    repository: "Torutesu/AIagentpass", workflowName: "Release candidate", workflowPath: ".github/workflows/release-candidate.yml", expectedEvent: "workflow_dispatch", expectedRunId: "42", expectedSha: SHA,
    expectedJobNames: ["verify-source", "signed-candidate"], expectedArtifactNames: ["notarized-release-candidate", "release-integrity-evidence"]
  }));
  assert.throws(() => assertGithubArtifacts({ ...artifacts, artifacts: artifacts.artifacts.map((artifact) => ({ ...artifact, digest: "sha256:" + "f".repeat(63) })) }, { ...evidence }, { expectedArtifactNames: ["notarized-release-candidate", "release-integrity-evidence"] }));
  assert.throws(() => assertGithubArtifacts({ ...artifacts, artifacts: artifacts.artifacts.map((artifact) => ({ ...artifact, workflow_run: { ...artifact.workflow_run, repository_id: 701 } })) }, { ...evidence }, { expectedArtifactNames: ["notarized-release-candidate", "release-integrity-evidence"] }));
});

test("binds the independent GitHub commit response to the source SHA and tree", () => {
  assert.deepEqual(assertGithubCommit({ sha: SHA, commit: { tree: { sha: TREE } } }, { repository: "Torutesu/AIagentpass", expectedSha: SHA }), { repository: "Torutesu/AIagentpass", commit_sha: SHA, tree_sha: TREE });
  assert.throws(() => assertGithubCommit({ sha: SHA, commit: { tree: { sha: "not-a-tree" } } }, { repository: "Torutesu/AIagentpass", expectedSha: SHA }));
  assert.throws(() => assertGithubCommit({ sha: "c".repeat(40), commit: { tree: { sha: TREE } } }, { repository: "Torutesu/AIagentpass", expectedSha: SHA }));
});

test("binds release, qualification, CI, manifest commit and independent tree exactly", () => {
  assert.deepEqual(assertSourceBinding({ releaseHeadSha: SHA, qualificationHeadSha: SHA, ciHeadSha: SHA, manifestSourceCommit: SHA, manifestSourceTree: TREE, independentTreeSha: TREE }), { source_commit: SHA, source_tree: TREE });
  assert.throws(() => assertSourceBinding({ releaseHeadSha: SHA, qualificationHeadSha: "c".repeat(40), ciHeadSha: SHA, manifestSourceCommit: SHA, manifestSourceTree: TREE, independentTreeSha: TREE }));
  assert.throws(() => assertSourceBinding({ releaseHeadSha: SHA, qualificationHeadSha: SHA, ciHeadSha: SHA, manifestSourceCommit: SHA, manifestSourceTree: TREE, independentTreeSha: "c".repeat(40) }));
});

test("scans protected artifacts and rejects secrets, symlinks, hardlinks, and opaque archives", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-ci-preflight-"));
  try {
    const clean = path.join(root, "clean.json");
    fs.writeFileSync(clean, "{\"ok\":true}\n");
    assert.equal(scanProtectedArtifacts([clean]).clean, true);
    const secret = path.join(root, "secret.txt");
    fs.writeFileSync(secret, "-----BEGIN PRIVATE KEY-----\n");
    assert.throws(() => scanProtectedArtifacts([secret]));
    const archive = path.join(root, "bundle.zip");
    fs.writeFileSync(archive, "not inspected");
    assert.throws(() => scanProtectedArtifacts([archive]));
    const symlink = path.join(root, "link");
    fs.symlinkSync(clean, symlink);
    assert.throws(() => scanProtectedArtifacts([symlink]));
    const hardlink = path.join(root, "hardlink");
    fs.linkSync(clean, hardlink);
    assert.throws(() => scanProtectedArtifacts([clean, hardlink]));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("CLI emits machine-readable evidence and fails closed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-ci-preflight-cli-"));
  try {
    const runFile = path.join(root, "run.json");
    const jobsFile = path.join(root, "jobs.json");
    fs.writeFileSync(runFile, JSON.stringify(ciRun));
    fs.writeFileSync(jobsFile, JSON.stringify({ total_count: 6, jobs: jobs() }));
    const script = path.resolve("scripts/release/ci-preflight.mjs");
    const ok = spawnSync(process.execPath, [script, "github", runFile, jobsFile, SHA, "Torutesu/AIagentpass"], { encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).terminal_results.length, 6);
    assert.equal(ok.stdout, `${canonicalJson(JSON.parse(ok.stdout))}\n`);
    const bad = spawnSync(process.execPath, [script, "github", runFile, jobsFile, "c".repeat(40), "Torutesu/AIagentpass"], { encoding: "utf8" });
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr, /ci preflight failed/u);
    fs.writeFileSync(jobsFile, JSON.stringify({ total_count: 7, jobs: jobs() }));
    const incomplete = spawnSync(process.execPath, [script, "github", runFile, jobsFile, SHA, "Torutesu/AIagentpass"], { encoding: "utf8" });
    assert.notEqual(incomplete.status, 0);
    assert.match(incomplete.stderr, /incomplete or paginated/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("external qualification CLI requires a complete authoritative binding file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-external-qualification-cli-"));
  try {
    const evidence = externalEvidence();
    const gateArtifacts = {};
    const gateJobIds = {};
    Object.entries(evidence.gates).forEach(([name, gate], index) => {
      gate.execution.artifact_sha256 = String(index + 1).repeat(64);
      gate.execution.job_id = String(2001 + index);
      gateArtifacts[name] = gate.execution.artifact_sha256;
      gateJobIds[name] = gate.execution.job_id;
    });
    const evidenceFile = path.join(root, "evidence.json");
    const bindingFile = path.join(root, "binding.json");
    fs.writeFileSync(evidenceFile, canonicalJson(evidence));
    fs.writeFileSync(bindingFile, canonicalJson({
      repository: "Torutesu/AIagentpass",
      source_commit: SHA,
      source_tree: TREE,
      release_artifact_sha256: "f".repeat(64),
      ci_run_id: "42",
      ci_run_attempt: "3",
      gate_artifacts: gateArtifacts,
      gate_job_ids: gateJobIds
    }));
    const script = path.resolve("scripts/release/ci-preflight.mjs");
    const ok = spawnSync(process.execPath, [script, "external-qualification", evidenceFile, bindingFile], { encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).status, "passed");
    const badBinding = JSON.parse(fs.readFileSync(bindingFile, "utf8"));
    delete badBinding.gate_job_ids.postgresql;
    fs.writeFileSync(bindingFile, canonicalJson(badBinding));
    const failed = spawnSync(process.execPath, [script, "external-qualification", evidenceFile, bindingFile], { encoding: "utf8" });
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /binding|job/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("workflow-evidence CLI binds real-shaped run, jobs, artifacts, and independent tree JSON without an API call", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-github-evidence-cli-"));
  try {
    const run = { ...ciRun, name: "Release candidate", path: ".github/workflows/release-candidate.yml", event: "workflow_dispatch" };
    const runFile = path.join(root, "run.json");
    const jobsFile = path.join(root, "jobs.json");
    const artifactsFile = path.join(root, "artifacts.json");
    fs.writeFileSync(runFile, JSON.stringify(run));
    fs.writeFileSync(jobsFile, JSON.stringify({ total_count: 2, jobs: [
      { id: 11, name: "verify-source", run_id: 42, run_attempt: 3, head_sha: SHA, status: "completed", conclusion: "success" },
      { id: 12, name: "signed-candidate", run_id: 42, run_attempt: 3, head_sha: SHA, status: "completed", conclusion: "success" }
    ] }));
    fs.writeFileSync(artifactsFile, JSON.stringify({ total_count: 2, artifacts: ["notarized-release-candidate", "release-integrity-evidence"].map((name, index) => ({
      id: 101 + index, name, expired: false, digest: `sha256:${String(index + 1).repeat(64)}`,
      workflow_run: { id: 42, repository_id: 700, head_repository_id: 700, workflow_id: 900, head_branch: "main", head_sha: SHA, event: "workflow_dispatch", status: "completed", conclusion: "success" }
    })) }));
    const script = path.resolve("scripts/release/ci-preflight.mjs");
    const args = [script, "github-evidence", runFile, jobsFile, artifactsFile, "Torutesu/AIagentpass", "Release candidate", ".github/workflows/release-candidate.yml", "workflow_dispatch", "42", SHA, "--job=verify-source", "--job=signed-candidate", "--artifact=notarized-release-candidate", "--artifact=release-integrity-evidence"];
    const ok = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).artifacts[0].digest, `sha256:${"1".repeat(64)}`);
    const bad = structuredClone(JSON.parse(fs.readFileSync(artifactsFile, "utf8")));
    bad.artifacts[0].digest = "sha256:" + "f".repeat(63);
    fs.writeFileSync(artifactsFile, JSON.stringify(bad));
    const failed = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /artifact|digest/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("both release workflows wire the binding validators before promotion or protected signing", () => {
  const releaseCandidate = fs.readFileSync(path.resolve(".github/workflows/release-candidate.yml"), "utf8");
  const promotion = fs.readFileSync(path.resolve(".github/workflows/promote-qualified-release.yml"), "utf8");
  assert.match(releaseCandidate, /ci-preflight\.mjs github[\s\S]*?ci-preflight\.mjs github-commit/u);
  assert.match(promotion, /ci-preflight\.mjs github-evidence[\s\S]*?ci-preflight\.mjs github-commit/u);
  assert.match(promotion, /sha256:\[0-9a-f\]\{64\}/u);
  assert.match(promotion, /tree_sha/iu);
});

test("produces reproducible evidence for plain files and tar variants while excluding only the evidence file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-artifact-scan-"));
  try {
    fs.writeFileSync(path.join(root, "manifest.json"), "{\"ok\":true}\n");
    const source = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-artifact-source-"));
    try {
      fs.writeFileSync(path.join(source, "nested.txt"), "safe\n");
      execFileSync("tar", ["-czf", path.join(root, "controller.tar.gz"), "-C", source, "nested.txt"]);
    } finally {
      fs.rmSync(source, { recursive: true, force: true });
    }
    const first = scanReleaseArtifacts(root, { exclude: ["artifact-scan.json"] });
    const second = scanReleaseArtifacts(root, { exclude: ["artifact-scan.json"] });
    assert.deepEqual(first, second);
    assert.deepEqual(first.files.map((item) => item.path), ["controller.tar.gz", "manifest.json"]);
    assert.equal(first.files[0].kind, "archive");
    assert.equal(first.files[0].scan.files[0].path, "nested.txt");
    fs.writeFileSync(path.join(root, "secret.txt"), "-----BEGIN PRIVATE KEY-----\n");
    assert.throws(() => scanReleaseArtifacts(root, { exclude: ["artifact-scan.json"] }), /secret material/u);
    fs.rmSync(path.join(root, "secret.txt"));
    fs.writeFileSync(path.join(root, "artifact-scan.json"), "ignored evidence\n");
    assert.deepEqual(scanReleaseArtifacts(root, { exclude: ["artifact-scan.json"] }), first);
    fs.writeFileSync(path.join(root, "invalid.pkg"), "not an Apple installer\n");
    assert.throws(() => scanReleaseArtifacts(root), /PKG expansion failed/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("scans the fd-bound snapshot instead of re-resolving a swappable release pathname", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-artifact-swap-"));
  const target = path.join(root, "controller.bin");
  const replacement = path.join(root, "replacement.bin");
  const parked = path.join(root, "parked.bin");
  const originalOpenSync = fs.openSync;
  let sourcePathOpenCount = 0;
  let swapped = false;
  try {
    fs.writeFileSync(target, "safe original\n");
    fs.writeFileSync(replacement, "safe alternate\n");
    fs.openSync = function patchedOpenSync(file, ...args) {
      if (typeof file === "string" && path.resolve(file) === target) {
        sourcePathOpenCount += 1;
        if (sourcePathOpenCount === 2) {
          fs.renameSync(target, parked);
          fs.renameSync(replacement, target);
          try {
            const fd = originalOpenSync.call(this, file, ...args);
            swapped = true;
            return fd;
          } finally {
            fs.renameSync(target, replacement);
            fs.renameSync(parked, target);
          }
        }
      }
      return originalOpenSync.call(this, file, ...args);
    };
    const evidence = scanReleaseArtifacts(root);
    assert.equal(swapped, false, "release scanner reopened the source pathname after fd binding");
    assert.equal(evidence.files[0].sha256, evidence.files[0].scan.files[0].sha256);
  } finally {
    fs.openSync = originalOpenSync;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
