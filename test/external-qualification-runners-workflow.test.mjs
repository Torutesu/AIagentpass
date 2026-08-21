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
    "AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_SHA256",
    "AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_SHA256",
    "git/commits/$AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT",
    "git/commits/$AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_COMMIT",
    "AGENTPASS_KMS_QUALIFICATION_RUN_ID=\"\$\{\{ needs\.validate\.outputs\.ci_run_id \}\}\"",
    "AGENTPASS_POSTGRES_QUALIFICATION_RUN_ID=\"\$\{\{ needs\.validate\.outputs\.ci_run_id \}\}\"",
    "actions/runs/$GITHUB_RUN_ID/jobs",
    "ci-preflight.mjs kms-qualification",
    "ci-preflight.mjs platform-auth-qualification",
    "qualification:webauthn:external",
    "qualification:postgres-c3:external",
    "AGENTPASS_C3_BACKUP_PITR_EVIDENCE",
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
});
