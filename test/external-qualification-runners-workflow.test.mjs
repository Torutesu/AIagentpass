import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/external-qualification-runners.yml", import.meta.url), "utf8");

test("external qualification runner workflow is protected and does not add canonical CI lanes", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  assert.match(workflow, /github\.repository == 'Torutesu\/AIagentpass'/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /validate:\n/);
  assert.match(workflow, /source_commit must be an exact 40-character SHA/);
  assert.match(workflow, /artifact_sha256 must be an exact SHA-256/);
  assert.match(workflow, /ci_run_id must be an exact run ID/);
  assert.match(workflow, /ci_run_attempt must be an exact attempt/);
  assert.match(workflow, /canonical CI run is not a successful terminal run/);
  assert.match(workflow, /git\/commits\/\$SOURCE_COMMIT/);
  assert.match(workflow, /needs: validate/);
  assert.match(workflow, /environment: external-qualification-kms/);
  assert.match(workflow, /environment: external-qualification-platform-auth/);
  assert.match(workflow, /environment: external-qualification-webauthn/);
  assert.match(workflow, /runs-on: \[self-hosted, agentpass-webauthn-qualification\]/);
  assert.match(workflow, /runs-on: \[self-hosted, agentpass-kms-qualification\]/);
  assert.match(workflow, /runs-on: \[self-hosted, agentpass-platform-auth-qualification\]/);
  assert.match(workflow, /runs-on: \[self-hosted, agentpass-postgresql-qualification-16\]/);
  assert.match(workflow, /runs-on: \[self-hosted, agentpass-postgresql-qualification-17\]/);
  assert.match(workflow, /environment: external-qualification-postgresql/);
  assert.match(workflow, /postgres-gate:/);
  assert.match(workflow, /needs: \[validate, postgres-authority-16, postgres-authority-17\]/);
  assert.match(workflow, /needs\['postgres-authority-16'\]\.result/);
  assert.match(workflow, /needs\['postgres-authority-17'\]\.result/);
  assert.doesNotMatch(workflow, /pull_request|schedule|workflow_run/);
});

test("external runner workflow binds source tree, run/job, adapter digest, and secret scan", () => {
  for (const value of [
    "AGENTPASS_KMS_PROVIDER_ADAPTER_SHA256",
    "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST",
    "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS",
    "AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_SHA256",
    "AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_SHA256",
    "git/commits/$AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT",
    "git/commits/$AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_COMMIT",
    "AGENTPASS_KMS_QUALIFICATION_CI_RUN_ID=\"\$\{\{ needs\.validate\.outputs\.ci_run_id \}\}\"",
    "AGENTPASS_POSTGRES_QUALIFICATION_CI_RUN_ID=\"\$\{\{ needs\.validate\.outputs\.ci_run_id \}\}\"",
    "actions/runs/$GITHUB_RUN_ID/jobs",
    "ci-preflight.mjs kms-qualification",
    "ci-preflight.mjs platform-auth-qualification",
    "qualification:webauthn:external",
    "qualification:postgres-c3:external",
    "AGENTPASS_C3_BACKUP_PITR_EVIDENCE",
    "AGENTPASS_POSTGRES_16_BACKUP_PITR_EVIDENCE_PATH",
    "AGENTPASS_POSTGRES_17_BACKUP_PITR_EVIDENCE_PATH",
    "postgres-16-backup-pitr.json",
    "postgres-17-backup-pitr.json",
    "AGENTPASS_POSTGRES_QUALIFICATION_ARTIFACT_SHA256",
    "select(.name == \"postgres-authority-16\") | .id",
    "select(.name == \"postgres-authority-17\") | .id",
    "AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION: isolated-disposable",
    "AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION: isolated-disposable",
    "qualification:postgres-gate:aggregate",
    "external-postgres-gate-",
    "children.bundle",
    "ci-preflight.mjs secret-scan"
  ]) assert.match(workflow, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  for (const use of workflow.matchAll(/uses:\s*([^\s]+)/g)) assert.match(use[1], /^actions\/(?:checkout|setup-node|upload-artifact|download-artifact)@[0-9a-f]{40}$/u);
  assert.doesNotMatch(workflow, /--job-id\s+postgres-authority-(?:16|17)(?:\s|$)/u);
  assert.match(workflow, /AGENTPASS_BACKUP_PITR_CI_JOB_ID="\$job_id"/u);
  assert.match(workflow, /AGENTPASS_WEBAUTHN_QUALIFICATION_RUN_ID="\$GITHUB_RUN_ID"/u);
  assert.match(workflow, /AGENTPASS_WEBAUTHN_QUALIFICATION_RUN_ATTEMPT="\$GITHUB_RUN_ATTEMPT"/u);
});

test("PostgreSQL protected lanes execute the live TLS/CA/disposable preflight before any database probe", () => {
  const lanes = [
    ["16", "postgres-authority-16", "AGENTPASS_EXTERNAL_POSTGRES_16"],
    ["17", "postgres-authority-17", "AGENTPASS_EXTERNAL_POSTGRES_17"]
  ];
  assert.equal((workflow.match(/npm run postgres:require-live-env/g) ?? []).length, lanes.length);
  for (const [major, job, prefix] of lanes) {
    const start = workflow.indexOf(`  ${job}:`);
    const nextJob = major === "16" ? "postgres-authority-17" : "postgres-gate";
    const end = workflow.indexOf(`\n  ${nextJob}:`, start + 1);
    assert.ok(start >= 0, `${job} is present`);
    const block = workflow.slice(start, end === -1 ? workflow.length : end);
    for (const value of [
      `runs-on: [self-hosted, agentpass-postgresql-qualification-${major}]`,
      "AGENTPASS_DATABASE_URL: ${{ secrets." + prefix + "_DATABASE_URL }}",
      "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL: ${{ secrets." + prefix + "_RESTORE_DATABASE_URL }}",
      "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL: ${{ secrets." + prefix + "_PITR_DATABASE_URL }}",
      "AGENTPASS_BACKUP_PITR_CA_CERT_FILE: ${{ vars." + prefix + "_CA_CERT_FILE }}",
      "AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION: isolated-disposable",
      "AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION: isolated-disposable",
      "AGENTPASS_BACKUP_PITR_RUNNER_ID: ${{ vars." + prefix + "_RUNNER_ID }}",
      "AGENTPASS_BACKUP_PITR_SOURCE_TREE=\"$source_tree\"",
      "AGENTPASS_BACKUP_PITR_CI_RUN_ID=\"${{ needs.validate.outputs.ci_run_id }}\"",
      "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT=\"${{ needs.validate.outputs.ci_run_attempt }}\"",
      "AGENTPASS_BACKUP_PITR_CI_JOB_ID=\"$job_id\"",
      "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256=\"$migration_artifact_sha256\"",
      "AGENTPASS_C3_REQUIRE_REAL_DATABASE: \"1\"",
      "checkout_commit=\"$(git rev-parse 'HEAD^{commit}')\"",
      "checkout_tree=\"$(git rev-parse 'HEAD^{tree}')\"",
      "AGENTPASS_TEST_DATABASE_URL: ${{ secrets." + prefix + "_DATABASE_URL }}",
      "AGENTPASS_C3_CA_CERT_FILE: ${{ vars." + prefix + "_CA_CERT_FILE }}",
      "npm run qualification:postgres-c3:external"
    ]) assert.ok(block.includes(value), `${job} contains ${value}`);
    const preflight = block.indexOf("npm run postgres:require-live-env");
    const backup = block.indexOf("node scripts/qualification/backup-pitr-evidence.mjs run");
    const strictShell = block.indexOf("set -euo pipefail");
    assert.ok(strictShell >= 0 && preflight > strictShell && backup > preflight, `${job} preflight is fail-closed before backup/PITR connection`);
  }
});
