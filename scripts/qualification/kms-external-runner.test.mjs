import assert from "node:assert/strict";
import test from "node:test";
import { KmsQualificationRunnerError, runExternalKmsQualification } from "./run-kms-qualification.mjs";

test("external KMS runner fails closed without protected execution mode", async () => {
  await assert.rejects(() => runExternalKmsQualification({ env: {} }), KmsQualificationRunnerError);
});

test("external KMS runner rejects local runner identity before loading an adapter", async () => {
  await assert.rejects(() => runExternalKmsQualification({ env: {
    AGENTPASS_KMS_QUALIFICATION_ENABLED: "true",
    AGENTPASS_KMS_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: "local-test",
  } }), KmsQualificationRunnerError);
});

test("external KMS runner requires an immutable adapter digest binding", async () => {
  await assert.rejects(() => runExternalKmsQualification({ env: {
    AGENTPASS_KMS_QUALIFICATION_ENABLED: "true",
    AGENTPASS_KMS_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: "protected-runner",
    AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT: "a".repeat(40),
    AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE: "b".repeat(40),
    AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST: "c".repeat(64),
    AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256: "d".repeat(64),
    AGENTPASS_KMS_QUALIFICATION_RUN_ID: "42",
    AGENTPASS_KMS_QUALIFICATION_JOB_ID: "1002",
    AGENTPASS_KMS_PROVIDER_ADAPTER_MODULE: "scripts/qualification/cloud-signer-kms.mjs",
    AGENTPASS_KMS_QUALIFICATION_EVIDENCE_PATH: "/tmp/agentpass-kms-evidence.json"
  } }), KmsQualificationRunnerError);
});
