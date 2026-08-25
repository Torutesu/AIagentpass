import assert from "node:assert/strict";
import test from "node:test";
import { PlatformAuthQualificationRunnerError, runExternalPlatformAuthQualification } from "./run-platform-auth-qualification.mjs";

test("external Platform Auth runner fails closed without explicit enablement", async () => {
  await assert.rejects(() => runExternalPlatformAuthQualification({ env: {} }), PlatformAuthQualificationRunnerError);
});

test("external Platform Auth runner rejects local runner identity", async () => {
  await assert.rejects(() => runExternalPlatformAuthQualification({ env: {
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUNNER_ID: "local-test"
  } }), PlatformAuthQualificationRunnerError);
});

test("external Platform Auth runner rejects an unmarked simulated execution", async () => {
  await assert.rejects(() => runExternalPlatformAuthQualification({ env: {
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUNNER_ID: "protected-runner"
  } }), PlatformAuthQualificationRunnerError);
});

test("external Platform Auth runner requires adapter provenance and complete deployment binding", async () => {
  await assert.rejects(() => runExternalPlatformAuthQualification({ env: {
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUNNER_ID: "protected-runner",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_COMMIT: "a".repeat(40),
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_TREE: "b".repeat(40),
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST: "c".repeat(64),
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST: "d".repeat(64),
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ID: "42",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_JOB_ID: "1002",
    AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_MODULE: "scripts/qualification/platform-auth.mjs",
    AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EVIDENCE_PATH: "/tmp/agentpass-platform-auth-evidence.json"
  } }), PlatformAuthQualificationRunnerError);
});
