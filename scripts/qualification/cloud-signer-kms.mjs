#!/usr/bin/env node

import crypto from "node:crypto";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  SIGNER_PURPOSE_REGISTRY,
  validateSignerPurposeBindings
} from "../../apps/cloud-api/src/signer-purpose-registry.mjs";
import {
  identityBindingDigest,
  normalizeKmsProviderIdentityAttestation,
  normalizeKmsProviderIdentityAttestorTrustInputs,
  verifyKmsProviderIdentityAttestation
} from "./kms-provider-identity-attestation.mjs";

export const CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION = 2;
export const CLOUD_SIGNER_KMS_QUALIFICATION_KIND = "agentpass-cloud-signer-kms-qualification";
export const CLOUD_SIGNER_KMS_PROVIDER_ADAPTER_CONTRACT_VERSION = 2;
export const CLOUD_SIGNER_KMS_PROVIDER_EVIDENCE_SCHEMA_VERSION = 1;
export const CLOUD_SIGNER_KMS_PROVIDER_EVIDENCE_KIND = "agentpass-cloud-signer-kms-provider-evidence";
export const CLOUD_SIGNER_KMS_IAM_ATTESTATION_SCHEMA_VERSION = 1;
export const CLOUD_SIGNER_KMS_IAM_ATTESTATION_KIND = "agentpass.kms-iam-policy-attestation";
export const CLOUD_SIGNER_KMS_IAM_ATTESTATION_DOMAIN = "AgentPass-KMS-IAM-Policy-Attestation-v1\0";
export const CLOUD_SIGNER_KMS_MAX_CREDENTIAL_TTL_MS = 15 * 60 * 1000;
export const CLOUD_SIGNER_KMS_SCENARIOS = Object.freeze([
  "provider_contract",
  "key_version_binding",
  "non_exportability",
  "rotation",
  "disable",
  "lifecycle_fence",
  "response_loss_reconciliation",
  "canary_sign_verify"
]);
export const CLOUD_SIGNER_KMS_PURPOSES = Object.freeze(
  Object.values(SIGNER_PURPOSE_REGISTRY).map((value) => value.name).sort()
);

const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const SOURCE_TREE = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const PUBLIC_KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const KEY_VERSION = /^[1-9][0-9]{0,19}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const UNKNOWN_IDENTITY = /(^|[._:/ -])(unknown|unidentified|unspecified|placeholder|redacted|n\/a|none|null)($|[._:/ -])/iu;
const PROVIDERS = new Set(["aws-kms", "gcp-cloud-kms", "hsm"]);
const STATUS = new Set(["passed", "failed"]);
const SAFE_REASONS = new Set([
  "provider_unavailable",
  "provider_timeout",
  "credentials_unavailable",
  "invalid_provider_output",
  "iam_probe_failed",
  "iam_mismatch",
  "provider_identity_mismatch",
  "non_exportable_violation",
  "canary_failed",
  "lifecycle_fenced",
  "reconciliation_uncertain",
  "postgres_qualification_failed",
  "incomplete_run",
  "invalid_source_binding",
  "invalid_deployment_binding",
  "invalid_artifact_binding",
  "invalid_run_binding",
  "execution_not_external",
  "provider_not_configured",
  "qualification_dependencies_missing",
  "provider_target_binding_missing",
  "provider_target_binding_invalid",
  "provider_identity_attestation_missing",
  "provider_identity_attestation_invalid",
  "credential_preflight_failed"
]);

const BINDING_KEYS = Object.freeze([
  "algorithm", "domain", "hosted_status", "key_id", "key_version", "name", "provider",
  "provider_resource_id", "public_key_fingerprint", "protocol_version", "purpose",
  "registry_version", "signing_version", "version"
]);
const PROVIDER_IDENTITY_KEYS = Object.freeze([
  "account_or_project", "authenticated", "challenge_digest", "credential_source", "identity", "identity_fingerprint",
  "observed_at", "proof_kind", "provider", "region", "response_digest"
]);
const PROVIDER_IDENTITY_ATTESTATION_KEYS = Object.freeze([...PROVIDER_IDENTITY_KEYS, "attestation"]);
const EXECUTION_KEYS = Object.freeze(["credential_mode", "environment", "real_execution", "runner_id"]);
const PROVIDER_EVIDENCE_KEYS = Object.freeze([
  "artifact_sha256", "deployment_digest", "details", "job_id", "key_id", "key_version", "kind",
  "purpose", "run_id", "scenario", "schema_version", "source_commit", "source_tree", "status"
]);
const REPORT_KEYS = Object.freeze([
  "artifact_sha256", "completed_at", "deployment_digest", "execution", "iam_matrix", "job_id", "kind", "postgres",
  "provider_identities", "purpose_bindings", "qualified", "reason", "run_id", "schema_version", "scenarios",
  "source_commit", "source_tree", "started_at", "status"
]);
const REPORT_KEYS_WITH_QUALIFICATION_BINDING = Object.freeze([...REPORT_KEYS, "ci_run_attempt", "ci_run_id", "qualification_job_id", "qualification_run_attempt", "qualification_run_id"]);
const NOT_RUN_KEYS = Object.freeze([
  "completed_at", "kind", "qualified", "reason", "schema_version", "started_at", "status"
]);
const EXPECTED_PROVIDER_BINDING_KEYS = Object.freeze([
  "account_or_project", "identity", "identity_fingerprint", "key_id", "key_version", "provider", "provider_resource_id", "public_key_fingerprint", "region"
]);
const EXPECTED_PROVIDER_BINDINGS_ENV = "AGENTPASS_KMS_QUALIFICATION_EXPECTED_BINDINGS";
const IDENTITY_ATTESTATION_TRUST_ENV = "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST";
const ATTESTOR_PUBLIC_KEYS_ENV = "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS";
const PROVIDER_IDENTITY_PROOF_KINDS = Object.freeze({
  "aws-kms": "aws_sts_get_caller_identity",
  "gcp-cloud-kms": "gcp_iam_credentials_principal",
  hsm: "hsm_attestation"
});
const IAM_ATTESTATION_KEYS = Object.freeze([
  "artifact_sha256", "attestor_key_id", "attestor_public_key_fingerprint", "deployment_digest", "expires_at",
  "identity", "identity_fingerprint", "issued_at", "kind", "policy_digest", "provider", "account_or_project",
  "region", "resource_ids", "run_id", "job_id", "schema_version", "signature_base64url", "source_commit", "source_tree"
]);
const IAM_ATTESTATION_PAYLOAD_KEYS = Object.freeze(IAM_ATTESTATION_KEYS.filter((key) => !["attestor_key_id", "attestor_public_key_fingerprint", "signature_base64url"].includes(key)));
const B64URL = /^[A-Za-z0-9_-]+$/u;
const CREDENTIAL_SOURCE = new Set(["aws_workload_identity", "gcp_workload_identity", "multi_provider_workload_identity"]);
const CREDENTIAL_SOURCE_ENV = "AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_SOURCE";
const CREDENTIAL_ISSUED_AT_ENV = "AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_ISSUED_AT";
const CREDENTIAL_EXPIRES_AT_ENV = "AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_EXPIRES_AT";
const CREDENTIAL_MAX_TTL_ENV = "AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MAX_TTL_SECONDS";
const IAM_ATTESTATION_ENV = "AGENTPASS_KMS_QUALIFICATION_IAM_ATTESTATION";

export const CLOUD_SIGNER_KMS_QUALIFICATION_ERROR_CODES = Object.freeze({
  CONFIG: "invalid_configuration",
  INPUT: "invalid_evidence",
  NOT_RUN: "not_run",
  FAILED: "qualification_failed"
});

export class CloudSignerKmsQualificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "CloudSignerKmsQualificationError";
    this.code = code;
  }
}

/**
 * The production adapter is deliberately structural and provider-neutral. The
 * adapter owns SDK/IAM/KMS calls; this module only accepts the five narrow
 * projections and never receives credentials or raw provider responses in the
 * report path.
 */
export function createCloudSignerKmsProviderAdapter({ identityProbe, purposeFactory, iamProbe, scenarioProbe, postgresProbe } = {}) {
  if ([identityProbe, purposeFactory, iamProbe, scenarioProbe, postgresProbe].some((value) => typeof value !== "function")) {
    throw new CloudSignerKmsQualificationError(CLOUD_SIGNER_KMS_QUALIFICATION_ERROR_CODES.CONFIG);
  }
  return Object.freeze({
    contract_version: CLOUD_SIGNER_KMS_PROVIDER_ADAPTER_CONTRACT_VERSION,
    identityProbe,
    purposeFactory,
    iamProbe,
    scenarioProbe,
    postgresProbe
  });
}

/**
 * Validate every protected input that can be checked without contacting a
 * provider. This is deliberately separate from the probe runner so a bad
 * target, stale IAM attestation, substituted candidate, or long-lived
 * credential cannot cause even one provider call.
 */
export function preflightCloudSignerKmsQualification({
  env = process.env,
  now = () => new Date(),
  sourceCommit = env.AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT,
  sourceTree = env.AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE,
  deploymentDigest = env.AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST,
  artifactSha256 = env.AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256,
  runId = env.AGENTPASS_KMS_QUALIFICATION_RUN_ID ?? env.GITHUB_RUN_ID,
  jobId = env.AGENTPASS_KMS_QUALIFICATION_JOB_ID,
  runnerId = env.AGENTPASS_KMS_QUALIFICATION_RUNNER_ID,
  credentialMode = env.AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MODE,
  expectedProviderBindings = env[EXPECTED_PROVIDER_BINDINGS_ENV],
  identityAttestationTrust = env[IDENTITY_ATTESTATION_TRUST_ENV],
  attestorPublicKeys = env[ATTESTOR_PUBLIC_KEYS_ENV],
  iamAttestation = env[IAM_ATTESTATION_ENV]
} = {}) {
  const preflightError = (reason) => {
    const error = new CloudSignerKmsQualificationError(CLOUD_SIGNER_KMS_QUALIFICATION_ERROR_CODES.CONFIG);
    error.preflight_reason = reason;
    throw error;
  };
  if (env.AGENTPASS_KMS_QUALIFICATION_ENABLED !== "true"
    || env.AGENTPASS_KMS_QUALIFICATION_EXECUTION !== "external"
    || env.AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION !== "true") preflightError("execution_not_external");
  if (typeof runnerId !== "string" || !IDENTIFIER.test(runnerId)
    || /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)(?:$|[._:/ -])/iu.test(runnerId)) {
    preflightError("execution_not_external");
  }
  if (!CREDENTIAL_SOURCE.has(credentialMode) || env[CREDENTIAL_SOURCE_ENV] !== credentialMode) preflightError("credential_preflight_failed");
  const startedAt = timestamp(now());
  const issuedAt = timestamp(env[CREDENTIAL_ISSUED_AT_ENV]);
  const expiresAt = timestamp(env[CREDENTIAL_EXPIRES_AT_ENV]);
  const maxTtlSeconds = Number(env[CREDENTIAL_MAX_TTL_ENV]);
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  const current = Date.parse(startedAt);
  if (!Number.isSafeInteger(maxTtlSeconds) || maxTtlSeconds < 1 || maxTtlSeconds > CLOUD_SIGNER_KMS_MAX_CREDENTIAL_TTL_MS / 1000
    || !Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued
    || expires - issued > maxTtlSeconds * 1000 || expires - issued > CLOUD_SIGNER_KMS_MAX_CREDENTIAL_TTL_MS
    || current < issued || current >= expires) preflightError("credential_preflight_failed");
  const bindingReason = invalidBindingReason({ sourceCommit, sourceTree, deploymentDigest, runId, jobId });
  if (bindingReason) preflightError(bindingReason);
  let bindings;
  let trustedAttestors;
  try {
    bindings = normalizeExpectedProviderBindings(expectedProviderBindings);
    trustedAttestors = normalizeKmsProviderIdentityAttestorTrustInputs({
      identityAttestationTrust,
      attestorPublicKeys,
      expectedProviders: new Set(Object.values(bindings ?? {}).map((item) => item.provider))
    });
  } catch {
    preflightError("provider_identity_attestation_invalid");
  }
  if (bindings === null) preflightError("provider_target_binding_missing");
  if (trustedAttestors === null) preflightError("provider_identity_attestation_missing");
  try {
    normalizeAndVerifyIamAttestation(iamAttestation, bindings, trustedAttestors, {
      source_commit: sourceCommit,
      source_tree: sourceTree,
      deployment_digest: deploymentDigest,
      artifact_sha256: artifactSha256,
      run_id: String(runId),
      job_id: String(jobId)
    }, current);
  } catch {
    preflightError("provider_identity_attestation_invalid");
  }
  return Object.freeze({
    source_commit: sourceCommit,
    source_tree: sourceTree,
    deployment_digest: deploymentDigest,
    artifact_sha256: artifactSha256,
    run_id: String(runId),
    job_id: String(jobId),
    runner_id: runnerId,
    credential_mode: credentialMode,
    provider_count: new Set(Object.values(bindings).map((item) => item.provider)).size,
    purpose_count: Object.keys(bindings).length
  });
}

/**
 * Run the provider-independent qualification boundary.  The runner has no
 * AWS/GCP SDK import and no provider call of its own: all cloud operations
 * arrive through narrow injected probes and are reduced immediately to the
 * typed, redacted records below.
 */
export async function runCloudSignerKmsQualification({
  env = process.env,
  now = () => new Date(),
  sourceCommit = env.AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT,
  sourceTree = env.AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE,
  deploymentDigest = env.AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST,
  artifactSha256 = env.AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256,
  runId = env.AGENTPASS_KMS_QUALIFICATION_RUN_ID ?? env.GITHUB_RUN_ID,
  jobId = env.AGENTPASS_KMS_QUALIFICATION_JOB_ID,
  runnerId = env.AGENTPASS_KMS_QUALIFICATION_RUNNER_ID,
  credentialMode = env.AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MODE,
  providerAdapter,
  identityProbe,
  purposeFactory,
  iamProbe,
  scenarioProbe,
  postgresProbe,
  expectedProviderBindings = env[EXPECTED_PROVIDER_BINDINGS_ENV],
  identityAttestationTrust = env[IDENTITY_ATTESTATION_TRUST_ENV],
  attestorPublicKeys = env[ATTESTOR_PUBLIC_KEYS_ENV]
} = {}) {
  const startedAt = timestamp(now());
  if (env.AGENTPASS_KMS_QUALIFICATION_ENABLED !== "true") {
    return notRunEvidence(startedAt, "provider_not_configured");
  }
  const injectedTestMode = env.AGENTPASS_KMS_QUALIFICATION_TEST_INJECTION === "true"
    && env.AGENTPASS_KMS_QUALIFICATION_EXECUTION === "injected_test"
    && providerAdapter === undefined
    && [identityProbe, purposeFactory, iamProbe, scenarioProbe, postgresProbe].every((probe) => typeof probe === "function");
  let preflight;
  if (!injectedTestMode) {
    try {
      preflight = preflightCloudSignerKmsQualification({
        env, now: () => new Date(startedAt), sourceCommit, sourceTree, deploymentDigest, artifactSha256, runId, jobId,
        runnerId, credentialMode, expectedProviderBindings, identityAttestationTrust, attestorPublicKeys
      });
    } catch (error) {
      return notRunEvidence(startedAt, error?.preflight_reason ?? "credential_preflight_failed");
    }
  }
  if (typeof identityProbe !== "function" || typeof purposeFactory !== "function" || typeof iamProbe !== "function"
    || typeof scenarioProbe !== "function" || typeof postgresProbe !== "function") {
    if (providerAdapter !== undefined) {
      try {
        ({ identityProbe, purposeFactory, iamProbe, scenarioProbe, postgresProbe } = createCloudSignerKmsProviderAdapter(providerAdapter));
      } catch {
        return notRunEvidence(startedAt, "qualification_dependencies_missing");
      }
    }
  }
  if (typeof identityProbe !== "function" || typeof purposeFactory !== "function" || typeof iamProbe !== "function"
    || typeof scenarioProbe !== "function" || typeof postgresProbe !== "function") {
    return notRunEvidence(startedAt, "qualification_dependencies_missing");
  }
  const bindingReason = invalidBindingReason({ sourceCommit, sourceTree, deploymentDigest, artifactSha256, runId, jobId });
  if (bindingReason) return notRunEvidence(startedAt, bindingReason);
  let expectedBindings;
  let trustedAttestors;
  try {
    expectedBindings = normalizeExpectedProviderBindings(expectedProviderBindings);
    trustedAttestors = normalizeKmsProviderIdentityAttestorTrustInputs({
      identityAttestationTrust,
      attestorPublicKeys,
      expectedProviders: new Set(Object.values(expectedBindings ?? {}).map((item) => item.provider))
    });
  } catch {
    return notRunEvidence(startedAt, "provider_identity_attestation_invalid");
  }
  if (expectedBindings === null) return notRunEvidence(startedAt, "provider_target_binding_missing");
  const verifyAttestation = true;
  if (trustedAttestors === null) return notRunEvidence(startedAt, "provider_identity_attestation_missing");

  try {
    // Every provider-side probe must receive the same immutable production
    // binding.  Identity-only binding is insufficient: a purpose, IAM, or
    // PostgreSQL probe could otherwise qualify a different deployment while
    // the aggregate report still carries the selected source/artifact IDs.
    const qualificationBinding = Object.freeze({
      source_commit: sourceCommit,
      source_tree: sourceTree,
      deployment_digest: deploymentDigest,
      artifact_sha256: artifactSha256,
      run_id: String(runId),
      job_id: String(jobId)
    });
    const execution = normalizeExecution(injectedTestMode
      ? { credential_mode: "test_injection", environment: "injected_test", real_execution: false, runner_id: "test-injection" }
      : { credential_mode: credentialMode, environment: "managed_kms", real_execution: true, runner_id: runnerId });
    const identityChallenges = Object.freeze(buildIdentityChallenges(expectedBindings, qualificationBinding, startedAt));
    let providerIdentities;
    try {
      providerIdentities = normalizeProviderIdentities(await identityProbe({
        source_commit: sourceCommit,
        source_tree: sourceTree,
        deployment_digest: deploymentDigest,
        artifact_sha256: artifactSha256,
        run_id: String(runId),
        job_id: String(jobId),
        binding: qualificationBinding,
        identity_challenges: identityChallenges
      }), { qualificationBinding, expectedBindings, trustedAttestors, now: Date.parse(timestamp(now())), verifyAttestation });
    } catch (error) {
      if (["credentials_unavailable", "provider_unavailable", "provider_timeout"].includes(error?.code)) {
        return notRunEvidence(startedAt, "credentials_unavailable");
      }
      throw error;
    }
    const handles = [];
    for (const name of CLOUD_SIGNER_KMS_PURPOSES) {
      const expected = SIGNER_PURPOSE_REGISTRY[name];
      const value = await purposeFactory({ name, expected, binding: qualificationBinding });
      handles.push(normalizePurposeHandle(value, expected));
    }
    const purposeBindings = Object.values(validateSignerPurposeBindings(handles.map(({ binding }) => binding)).bindings);
    assertProviderIdentityCoverage(providerIdentities, purposeBindings);
    assertExpectedProviderBindings(providerIdentities, purposeBindings, expectedBindings);

    const iamMatrix = [];
    for (const caller of CLOUD_SIGNER_KMS_PURPOSES) {
      for (const target of CLOUD_SIGNER_KMS_PURPOSES) {
        const value = await iamProbe({
          caller_purpose: caller,
          key_purpose: target,
          caller: handles.find((item) => item.binding.name === caller).handle,
          target: handles.find((item) => item.binding.name === target).handle,
          binding: qualificationBinding
        });
        iamMatrix.push(normalizeIamResult(value, caller, target));
      }
    }
    assertIamMatrix(iamMatrix);

    const scenarios = [];
    for (const item of handles) {
      for (const scenario of CLOUD_SIGNER_KMS_SCENARIOS) {
        const value = await scenarioProbe({
          purpose: item.binding.purpose,
          name: item.binding.name,
          scenario,
          expected: item.binding,
          handle: item.handle,
          binding: qualificationBinding
        });
        scenarios.push(normalizeScenarioResult(value, item.binding, scenario, qualificationBinding));
      }
    }
    const postgres = normalizePostgresEvidence(await postgresProbe({ binding: qualificationBinding }));
    const completedAt = timestamp(now());
    const failed = iamMatrix.some((item) => item.decision !== expectedIamDecision(item.caller_purpose, item.key_purpose))
      || scenarios.some((item) => item.status !== "passed") || postgres.status !== "passed";
    return normalizeCloudSignerKmsQualificationEvidence({
      schema_version: CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION,
      kind: CLOUD_SIGNER_KMS_QUALIFICATION_KIND,
      status: failed ? "failed" : "passed",
      qualified: !failed,
      reason: failed ? failureReason(iamMatrix, scenarios, postgres) : null,
      source_commit: sourceCommit,
      source_tree: sourceTree,
      deployment_digest: deploymentDigest,
      artifact_sha256: artifactSha256,
      execution,
      provider_identities: providerIdentities,
      run_id: String(runId),
      job_id: String(jobId),
      started_at: startedAt,
      completed_at: completedAt,
      purpose_bindings: [...purposeBindings],
      iam_matrix: iamMatrix,
      scenarios,
      postgres
    });
  } catch (error) {
    return failedEvidence(startedAt, safeReason(error), sourceCommit, sourceTree, deploymentDigest, artifactSha256, runId, jobId);
  }
}

export function createCloudSignerKmsQualificationRunner(dependencies = {}) {
  return Object.freeze({ run: (options = {}) => runCloudSignerKmsQualification({ ...dependencies, ...options }) });
}

export function normalizeCloudSignerKmsQualificationEvidence(value) {
  try {
    const hasQualificationBinding = Object.prototype.hasOwnProperty.call(value, "ci_run_id");
    exactObject(value, hasQualificationBinding ? REPORT_KEYS_WITH_QUALIFICATION_BINDING : REPORT_KEYS);
    if (value.schema_version !== CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION
      || value.kind !== CLOUD_SIGNER_KMS_QUALIFICATION_KIND
      || value.status !== "passed" && value.status !== "failed"
      || value.qualified !== (value.status === "passed")
      || (value.reason !== null && !SAFE_REASONS.has(value.reason))
      || typeof value.source_commit !== "string" || !SOURCE_COMMIT.test(value.source_commit)
      || typeof value.source_tree !== "string" || !SOURCE_TREE.test(value.source_tree)
      || typeof value.deployment_digest !== "string" || !DIGEST.test(value.deployment_digest)
      || typeof value.artifact_sha256 !== "string" || !DIGEST.test(value.artifact_sha256)
      || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
      || typeof value.job_id !== "string" || !RUN_ID.test(value.job_id)) fail();
    if (hasQualificationBinding && ["ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id"].some((key) => typeof value[key] !== "string" || !RUN_ID.test(value[key]))) fail();
    timestamp(value.started_at);
    timestamp(value.completed_at);
    if (Date.parse(value.completed_at) < Date.parse(value.started_at)) fail();
    if (value.status === "failed" && value.reason === null) fail();
    if (value.status === "failed" && value.reason !== null
      && Array.isArray(value.purpose_bindings) && value.purpose_bindings.length === 0
      && Array.isArray(value.iam_matrix) && value.iam_matrix.length === 0
      && Array.isArray(value.scenarios) && value.scenarios.length === 0
      && value.execution === null
      && Array.isArray(value.provider_identities) && value.provider_identities.length === 0
      && plainExactObject(value.postgres, ["instances", "status"])
      && value.postgres.status === "failed" && Array.isArray(value.postgres.instances) && value.postgres.instances.length === 0) {
      return deepFreeze(structuredClone(value));
    }
    if (!Array.isArray(value.purpose_bindings) || value.purpose_bindings.length !== CLOUD_SIGNER_KMS_PURPOSES.length) fail();
    normalizeExecution(value.execution);
    const providerIdentities = normalizeProviderIdentities(value.provider_identities, {
      qualificationBinding: {
        source_commit: value.source_commit,
        source_tree: value.source_tree,
        deployment_digest: value.deployment_digest,
        artifact_sha256: value.artifact_sha256,
        run_id: value.run_id,
        job_id: value.job_id
      }
    });
    const bindings = value.purpose_bindings.map(normalizeBinding);
    validateSignerPurposeBindings(bindings);
    if (!sameArray(bindings.map((item) => item.name), CLOUD_SIGNER_KMS_PURPOSES)) fail();
    assertProviderIdentityCoverage(providerIdentities, bindings);
    const iamMatrix = normalizeIamMatrix(value.iam_matrix);
    const scenarios = normalizeScenarioList(value.scenarios, bindings, {
      source_commit: value.source_commit,
      source_tree: value.source_tree,
      deployment_digest: value.deployment_digest,
      artifact_sha256: value.artifact_sha256,
      run_id: value.run_id,
      job_id: value.job_id
    });
    normalizePostgresEvidence(value.postgres);
    if (value.status === "passed" && (value.reason !== null || iamMatrix.some((item) => item.decision !== expectedIamDecision(item.caller_purpose, item.key_purpose))
      || scenarios.some((item) => item.status !== "passed") || value.postgres.status !== "passed")) fail();
    return deepFreeze(structuredClone(value));
  } catch (error) {
    if (error instanceof CloudSignerKmsQualificationError) throw error;
    fail();
  }
}

export function normalizeCloudSignerKmsNotRunEvidence(value) {
  try {
    exactObject(value, NOT_RUN_KEYS);
    if (value.schema_version !== CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION
      || value.kind !== CLOUD_SIGNER_KMS_QUALIFICATION_KIND || value.status !== "not_run"
      || value.qualified !== false || !SAFE_REASONS.has(value.reason)) fail();
    timestamp(value.started_at);
    timestamp(value.completed_at);
    if (Date.parse(value.completed_at) < Date.parse(value.started_at)) fail();
    if (!["provider_not_configured", "execution_not_external", "credentials_unavailable", "provider_unavailable", "provider_timeout", "qualification_dependencies_missing", "provider_target_binding_missing", "provider_target_binding_invalid", "provider_identity_attestation_missing", "provider_identity_attestation_invalid", "invalid_source_binding", "invalid_deployment_binding", "invalid_run_binding"].includes(value.reason)) fail();
    return deepFreeze(structuredClone(value));
  } catch (error) {
    if (error instanceof CloudSignerKmsQualificationError) throw error;
    fail();
  }
}

export function verifyCloudSignerKmsQualificationEvidence(input, {
  expectedSourceCommit,
  expectedSourceTree,
  expectedDeploymentDigest,
  expectedArtifactSha256,
  expectedRunId,
  expectedJobId,
  requireProviderIdentityAttestation = true
} = {}) {
  let value;
  let text;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array || typeof input === "string") {
    try {
      text = Buffer.from(input).toString("utf8");
      value = JSON.parse(text);
    } catch {
      fail();
    }
  } else {
    value = input;
  }
  const normalized = value?.status === "not_run"
    ? normalizeCloudSignerKmsNotRunEvidence(value)
    : normalizeCloudSignerKmsQualificationEvidence(value);
  if (requireProviderIdentityAttestation && normalized.status === "passed"
    && normalized.provider_identities.some((item) => !Object.prototype.hasOwnProperty.call(item, "attestation")
      || [item.account_or_project, item.identity, item.region].some((field) => typeof field !== "string" || UNKNOWN_IDENTITY.test(field)))) fail();
  if (normalized.status !== "not_run") {
    if (expectedSourceCommit !== undefined && normalized.source_commit !== expectedSourceCommit) fail();
    if (expectedSourceTree !== undefined && normalized.source_tree !== expectedSourceTree) fail();
    if (expectedDeploymentDigest !== undefined && normalized.deployment_digest !== expectedDeploymentDigest) fail();
    if (expectedArtifactSha256 !== undefined && normalized.artifact_sha256 !== expectedArtifactSha256) fail();
    if (expectedRunId !== undefined && normalized.run_id !== String(expectedRunId)) fail();
    if (expectedJobId !== undefined && normalized.job_id !== String(expectedJobId)) fail();
  }
  if (text !== undefined && canonicalCloudSignerKmsQualificationEvidence(normalized) !== text) fail();
  return Object.freeze({
    status: normalized.status,
    qualified: normalized.qualified,
    evidence_sha256: cloudSignerKmsQualificationSHA256(normalized),
    ...(normalized.status === "not_run"
      ? { reason: normalized.reason }
      : {
        source_commit: normalized.source_commit,
        source_tree: normalized.source_tree,
        deployment_digest: normalized.deployment_digest,
        artifact_sha256: normalized.artifact_sha256,
        run_id: normalized.run_id,
        job_id: normalized.job_id
      })
  });
}

export function canonicalCloudSignerKmsQualificationEvidence(value) {
  const normalized = value?.status === "not_run"
    ? normalizeCloudSignerKmsNotRunEvidence(value)
    : normalizeCloudSignerKmsQualificationEvidence(value);
  return canonicalJson(normalized);
}

export function cloudSignerKmsQualificationSHA256(value) {
  const normalized = value?.status === "not_run"
    ? normalizeCloudSignerKmsNotRunEvidence(value)
    : normalizeCloudSignerKmsQualificationEvidence(value);
  return crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex");
}

function normalizePurposeHandle(value, expected) {
  exactObject(value, ["binding", "handle"]);
  const binding = normalizeBinding(value.binding);
  if (binding.name !== expected.name || binding.purpose !== expected.purpose
    || binding.protocol_version !== expected.protocol_version || binding.signing_version !== expected.signing_version
    || binding.domain !== expected.domain || binding.hosted_status !== expected.hosted_status) fail();
  if (value.handle === null || (typeof value.handle !== "object" && typeof value.handle !== "function")) fail();
  return Object.freeze({ binding, handle: value.handle });
}

function normalizeExecution(value) {
  exactObject(value, EXECUTION_KEYS);
  if (value.credential_mode === "test_injection") {
    if (value.environment !== "injected_test" || value.real_execution !== false || value.runner_id !== "test-injection") fail();
    return Object.freeze({ ...value });
  }
  if (!["aws_workload_identity", "gcp_workload_identity", "multi_provider_workload_identity"].includes(value.credential_mode)
    || value.environment !== "managed_kms" || value.real_execution !== true
    || typeof value.runner_id !== "string" || !IDENTIFIER.test(value.runner_id)
    || /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)(?:$|[._:/ -])/iu.test(value.runner_id)) fail();
  return Object.freeze({ ...value });
}

export function identityChallengeDigest(provider, qualificationBinding) {
  if (!PROVIDERS.has(provider) || qualificationBinding === null || typeof qualificationBinding !== "object") fail();
  const challenge = {
    domain: "AgentPass-KMS-Provider-Identity-Challenge-v1",
    provider,
    source_commit: qualificationBinding.source_commit,
    source_tree: qualificationBinding.source_tree,
    deployment_digest: qualificationBinding.deployment_digest,
    artifact_sha256: qualificationBinding.artifact_sha256,
    run_id: qualificationBinding.run_id,
    job_id: qualificationBinding.job_id
  };
  return crypto.createHash("sha256").update(canonicalJson(challenge), "utf8").digest("hex");
}

export function identityAttestationNonce(provider, qualificationBinding) {
  return crypto.createHash("sha256").update(canonicalJson({
    domain: "AgentPass-KMS-Provider-Identity-Attestation-Nonce-v1",
    provider,
    ...qualificationBinding
  }), "utf8").digest("base64url");
}

function buildIdentityChallenges(expectedBindings, qualificationBinding, issuedAt) {
  const result = [];
  for (const provider of [...new Set(Object.values(expectedBindings).map((item) => item.provider))].sort()) {
    const bindings = Object.values(expectedBindings).filter((item) => item.provider === provider);
    const first = bindings[0];
    const resourceIds = bindings.map((item) => item.provider_resource_id).sort();
    result.push(Object.freeze({
      provider,
      nonce: identityAttestationNonce(provider, qualificationBinding),
      binding_digest: identityBindingDigest({ ...qualificationBinding, provider, account_or_project: first.account_or_project, identity: first.identity, identity_fingerprint: first.identity_fingerprint, region: first.region, resource_ids: resourceIds }),
      resource_ids: Object.freeze(resourceIds),
      issued_at: issuedAt,
      expires_at: new Date(Date.parse(issuedAt) + 300_000).toISOString()
    }));
  }
  return result;
}

function normalizeProviderIdentities(value, { qualificationBinding, expectedBindings, trustedAttestors, now = Date.now(), verifyAttestation = false } = {}) {
  if (!Array.isArray(value) || value.length < 2) fail();
  const result = value.map((item) => {
    exactObject(item, Object.prototype.hasOwnProperty.call(item, "attestation") ? PROVIDER_IDENTITY_ATTESTATION_KEYS : PROVIDER_IDENTITY_KEYS);
    if (!PROVIDERS.has(item.provider) || typeof item.account_or_project !== "string" || !IDENTIFIER.test(item.account_or_project)
      || typeof item.identity !== "string" || !IDENTIFIER.test(item.identity)
      || typeof item.identity_fingerprint !== "string" || !FINGERPRINT.test(item.identity_fingerprint)
      || typeof item.region !== "string" || !IDENTIFIER.test(item.region)
      || UNKNOWN_IDENTITY.test(item.account_or_project) || UNKNOWN_IDENTITY.test(item.identity) || UNKNOWN_IDENTITY.test(item.region)
      || typeof item.credential_source !== "string" || !["aws_workload_identity", "gcp_workload_identity", "hsm_workload_identity"].includes(item.credential_source)
      || typeof item.challenge_digest !== "string" || !DIGEST.test(item.challenge_digest)
      || typeof item.observed_at !== "string" || !TIMESTAMP.test(item.observed_at)
      || item.authenticated !== true
      || item.proof_kind !== PROVIDER_IDENTITY_PROOF_KINDS[item.provider]
      || typeof item.response_digest !== "string" || !DIGEST.test(item.response_digest)) fail();
    if (qualificationBinding !== undefined && item.challenge_digest !== identityChallengeDigest(item.provider, qualificationBinding)) fail();
    if (verifyAttestation && expectedBindings !== undefined && trustedAttestors !== undefined && trustedAttestors !== null) {
      const expected = Object.values(expectedBindings).filter((candidate) => candidate.provider === item.provider);
      const trust = trustedAttestors[item.provider];
      if (!trust || expected.length === 0 || !Object.prototype.hasOwnProperty.call(item, "attestation")) fail();
      const resourceIds = expected.map((candidate) => candidate.provider_resource_id).sort();
      const first = expected[0];
      const expectedBindingDigest = identityBindingDigest({
        ...qualificationBinding,
        provider: item.provider,
        account_or_project: first.account_or_project,
        identity: first.identity,
        identity_fingerprint: first.identity_fingerprint,
        region: first.region,
        resource_ids: resourceIds
      });
      const expectedNonce = identityAttestationNonce(item.provider, qualificationBinding);
      let attestation;
      try {
        attestation = verifyAttestation
          ? verifyKmsProviderIdentityAttestation(item.attestation, {
            trustedPublicKey: Buffer.from(trust.public_key_der_base64url, "base64url"),
            expectedNonce,
            expectedBindingDigest,
            now
          })
          : normalizeKmsProviderIdentityAttestation(item.attestation, {
            enforceValidity: false
          });
      } catch {
        fail();
      }
      if (attestation.attestor_key_id !== trust.key_id
        || attestation.provider !== item.provider
        || attestation.account_or_project !== item.account_or_project
        || attestation.identity !== item.identity
        || attestation.identity_fingerprint !== item.identity_fingerprint
        || attestation.region !== item.region
        || JSON.stringify([...attestation.resource_ids].sort()) !== JSON.stringify(resourceIds)
        || item.observed_at !== attestation.challenge.issued_at
        || item.response_digest !== attestation.provider_claims.response_digest) fail();
    } else if (Object.prototype.hasOwnProperty.call(item, "attestation")) {
      normalizeKmsProviderIdentityAttestation(item.attestation, { enforceValidity: false });
    }
    return Object.freeze({ ...item });
  });
  if (new Set(result.map((item) => item.provider)).size !== result.length) fail();
  return Object.freeze(result);
}

function normalizeExpectedProviderBindings(value) {
  if (value === undefined || value === null || value === "") return null;
  let parsed = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); } catch { fail(); }
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) fail();
  const names = Object.keys(parsed).sort();
  if (!sameArray(names, [...CLOUD_SIGNER_KMS_PURPOSES].sort())) fail();
  const result = Object.create(null);
  for (const name of CLOUD_SIGNER_KMS_PURPOSES) {
    const item = parsed[name];
    exactObject(item, EXPECTED_PROVIDER_BINDING_KEYS);
    if (!new Set(["aws-kms", "gcp-cloud-kms"]).has(item.provider)
      || typeof item.account_or_project !== "string" || !IDENTIFIER.test(item.account_or_project)
      || typeof item.identity !== "string" || !IDENTIFIER.test(item.identity)
      || typeof item.identity_fingerprint !== "string" || !FINGERPRINT.test(item.identity_fingerprint)
      || typeof item.key_id !== "string" || !IDENTIFIER.test(item.key_id)
      || typeof item.key_version !== "string" || !KEY_VERSION.test(item.key_version)
      || typeof item.region !== "string" || !IDENTIFIER.test(item.region)
      || UNKNOWN_IDENTITY.test(item.account_or_project) || UNKNOWN_IDENTITY.test(item.identity) || UNKNOWN_IDENTITY.test(item.region)
      || typeof item.provider_resource_id !== "string" || !IDENTIFIER.test(item.provider_resource_id)
      || typeof item.public_key_fingerprint !== "string" || !FINGERPRINT.test(item.public_key_fingerprint)
      || !providerResourceMatchesExpected(item)) fail();
    result[name] = Object.freeze({ ...item });
  }
  return Object.freeze(result);
}

export function iamAttestationSigningData(value) {
  const payload = Object.fromEntries(IAM_ATTESTATION_PAYLOAD_KEYS.map((key) => [key, value[key]]));
  return Buffer.concat([
    Buffer.from(CLOUD_SIGNER_KMS_IAM_ATTESTATION_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(payload), "utf8")
  ]);
}

function normalizeAndVerifyIamAttestation(value, bindings, trustedAttestors, qualificationBinding, now) {
  const reject = () => fail();
  let parsed = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); } catch { reject(); }
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || Object.getPrototypeOf(parsed) !== Object.prototype) reject();
  const providers = [...new Set(Object.values(bindings).map((item) => item.provider))].sort();
  if (!sameArray(Object.keys(parsed).sort(), providers)) reject();
  for (const provider of providers) {
    const item = parsed[provider];
    exactObject(item, IAM_ATTESTATION_KEYS);
    const expected = Object.values(bindings).filter((candidate) => candidate.provider === provider);
    const first = expected[0];
    const resourceIds = expected.map((candidate) => candidate.provider_resource_id).sort();
    if (item.schema_version !== CLOUD_SIGNER_KMS_IAM_ATTESTATION_SCHEMA_VERSION
      || item.kind !== CLOUD_SIGNER_KMS_IAM_ATTESTATION_KIND
      || item.provider !== provider
      || item.account_or_project !== first.account_or_project
      || item.identity !== first.identity
      || item.identity_fingerprint !== first.identity_fingerprint
      || item.region !== first.region
      || !sameArray([...item.resource_ids].sort(), resourceIds)
      || item.source_commit !== qualificationBinding.source_commit
      || item.source_tree !== qualificationBinding.source_tree
      || item.deployment_digest !== qualificationBinding.deployment_digest
      || item.artifact_sha256 !== qualificationBinding.artifact_sha256
      || item.run_id !== qualificationBinding.run_id
      || item.job_id !== qualificationBinding.job_id
      || !DIGEST.test(item.policy_digest)
      || !PUBLIC_KEY_FINGERPRINT.test(item.attestor_public_key_fingerprint)
      || !B64URL.test(item.signature_base64url)) reject();
    const issued = Date.parse(timestamp(item.issued_at));
    const expires = Date.parse(timestamp(item.expires_at));
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued
      || expires - issued > CLOUD_SIGNER_KMS_MAX_CREDENTIAL_TTL_MS || now < issued || now >= expires) reject();
    const trust = trustedAttestors[provider];
    if (!trust || item.attestor_key_id !== trust.key_id
      || item.attestor_public_key_fingerprint !== trust.public_key_fingerprint) reject();
    const key = crypto.createPublicKey({ key: Buffer.from(trust.public_key_der_base64url, "base64url"), format: "der", type: "spki" });
    if (!crypto.verify(null, iamAttestationSigningData(item), key, Buffer.from(item.signature_base64url, "base64url"))) reject();
  }
  return true;
}

function providerResourceMatchesExpected(item) {
  if (item.provider === "aws-kms") {
    return new RegExp(`^arn:aws:kms:${escapeRegExp(item.region)}:${escapeRegExp(item.account_or_project)}:key/${escapeRegExp(item.key_id)}$`, "u").test(item.provider_resource_id);
  }
  return new RegExp(`^projects/${escapeRegExp(item.account_or_project)}/locations/${escapeRegExp(item.region)}/keyRings/[A-Za-z0-9._-]+/cryptoKeys/${escapeRegExp(item.key_id)}/cryptoKeyVersions/${escapeRegExp(item.key_version)}$`, "u").test(item.provider_resource_id);
}

function assertExpectedProviderBindings(providerIdentities, purposeBindings, expectedBindings) {
  const identities = new Map(providerIdentities.map((item) => [item.provider, item]));
  for (const binding of purposeBindings) {
    const expected = expectedBindings[binding.name];
    const identity = identities.get(binding.provider);
    if (!expected || !identity
      || expected.provider !== binding.provider
      || expected.provider_resource_id !== binding.provider_resource_id
      || expected.key_id !== binding.key_id
      || expected.key_version !== binding.key_version
      || expected.public_key_fingerprint !== binding.public_key_fingerprint
      || expected.account_or_project !== identity.account_or_project
      || expected.region !== identity.region
      || expected.identity !== identity.identity
      || expected.identity_fingerprint !== identity.identity_fingerprint) fail();
  }
}

function assertProviderIdentityCoverage(providerIdentities, purposeBindings) {
  const identities = new Map(providerIdentities.map((item) => [item.provider, item]));
  for (const binding of purposeBindings) {
    const identity = identities.get(binding.provider);
    if (!identity || identity.authenticated !== true) fail();
    if ((binding.provider === "aws-kms" && identity.credential_source !== "aws_workload_identity")
      || (binding.provider === "gcp-cloud-kms" && identity.credential_source !== "gcp_workload_identity")) fail();
    if (!providerIdentityMatchesResource(identity, binding.provider_resource_id, binding.provider)) fail();
  }
}

function providerIdentityMatchesResource(identity, resource, provider) {
  if (provider === "aws-kms") {
    const match = /^arn:aws:kms:([^:]+):([0-9]{12}):key\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.exec(resource);
    return match !== null && match[1] === identity.region && match[2] === identity.account_or_project;
  }
  if (provider === "gcp-cloud-kms") {
    const match = /^projects\/([A-Za-z0-9._-]+)\/locations\/([A-Za-z0-9._-]+)\/keyRings\/[A-Za-z0-9._-]+\/cryptoKeys\/[A-Za-z0-9._-]+\/cryptoKeyVersions\/[1-9][0-9]{0,19}$/u.exec(resource);
    return match !== null && match[1] === identity.account_or_project && match[2] === identity.region;
  }
  // The current HSM resource contract does not carry a provider account or
  // region in a machine-parseable position. Do not qualify it until that
  // contract is versioned; an authenticated identity alone is insufficient.
  return false;
}

function normalizeBinding(value) {
  exactObject(value, BINDING_KEYS);
  for (const key of ["name", "purpose", "key_id", "key_version", "provider", "provider_resource_id"]) {
    if (typeof value[key] !== "string" || !IDENTIFIER.test(value[key])) fail();
  }
  if (!KEY_VERSION.test(value.key_version)) fail();
  if (typeof value.domain !== "string" || value.domain.length < 1 || value.domain.length > 128
    || typeof value.hosted_status !== "string" || value.hosted_status.length < 1 || value.hosted_status.length > 64
    || !PROVIDERS.has(value.provider) || value.algorithm !== "ed25519"
    || !Number.isSafeInteger(value.version) || value.version < 1
    || !Number.isSafeInteger(value.registry_version) || value.registry_version < 1
    || !Number.isSafeInteger(value.protocol_version) || value.protocol_version < 1
    || !Number.isSafeInteger(value.signing_version) || value.signing_version < 1
    || !FINGERPRINT.test(value.public_key_fingerprint)) fail();
  if (value.provider === "aws-kms"
    && !new RegExp(`^arn:aws:kms:[A-Za-z0-9-]+:[0-9]{12}:key/${escapeRegExp(value.key_id)}$`, "u").test(value.provider_resource_id)) fail();
  if (value.provider === "gcp-cloud-kms"
    && !new RegExp(`^projects/[A-Za-z0-9._-]+/locations/[A-Za-z0-9._-]+/keyRings/[A-Za-z0-9._-]+/cryptoKeys/${escapeRegExp(value.key_id)}/cryptoKeyVersions/${value.key_version}$`, "u").test(value.provider_resource_id)) fail();
  if (value.provider === "hsm"
    && !new RegExp(`^hsm://[A-Za-z0-9._:/-]+/${escapeRegExp(value.key_id)}/versions/${value.key_version}$`, "u").test(value.provider_resource_id)) fail();
  return Object.freeze({ ...value });
}

function normalizeIamResult(value, caller, target) {
  exactObject(value, ["decision"]);
  if (value.decision !== "allow" && value.decision !== "deny") fail();
  return Object.freeze({ caller_purpose: caller, key_purpose: target, decision: value.decision });
}

function normalizeIamMatrix(value) {
  if (!Array.isArray(value) || value.length !== CLOUD_SIGNER_KMS_PURPOSES.length ** 2) fail();
  const result = value.map((item, index) => {
    const caller = CLOUD_SIGNER_KMS_PURPOSES[Math.floor(index / CLOUD_SIGNER_KMS_PURPOSES.length)];
    const target = CLOUD_SIGNER_KMS_PURPOSES[index % CLOUD_SIGNER_KMS_PURPOSES.length];
    exactObject(item, ["caller_purpose", "decision", "key_purpose"]);
    if (item.caller_purpose !== caller || item.key_purpose !== target) fail();
    return normalizeIamResult({ decision: item.decision }, caller, target);
  });
  assertIamMatrix(result);
  return Object.freeze(result);
}

export function normalizeCloudSignerKmsProviderEvidence(value, {
  binding,
  scenario,
  qualificationBinding
} = {}) {
  try {
    exactObject(value, PROVIDER_EVIDENCE_KEYS);
    if (value.schema_version !== CLOUD_SIGNER_KMS_PROVIDER_EVIDENCE_SCHEMA_VERSION
      || value.kind !== CLOUD_SIGNER_KMS_PROVIDER_EVIDENCE_KIND
      || !STATUS.has(value.status)
      || typeof value.purpose !== "string"
      || typeof value.scenario !== "string"
      || !CLOUD_SIGNER_KMS_SCENARIOS.includes(value.scenario)
      || typeof value.key_id !== "string" || !IDENTIFIER.test(value.key_id)
      || typeof value.key_version !== "string" || !KEY_VERSION.test(value.key_version)
      || typeof value.source_commit !== "string" || !SOURCE_COMMIT.test(value.source_commit)
      || typeof value.source_tree !== "string" || !SOURCE_TREE.test(value.source_tree)
      || typeof value.deployment_digest !== "string" || !DIGEST.test(value.deployment_digest)
      || typeof value.artifact_sha256 !== "string" || !DIGEST.test(value.artifact_sha256)
      || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
      || typeof value.job_id !== "string" || !RUN_ID.test(value.job_id)) fail();
    if (binding !== undefined && (value.purpose !== binding.purpose || value.key_id !== binding.key_id
      || value.key_version !== binding.key_version)) fail();
    if (scenario !== undefined && value.scenario !== scenario) fail();
    if (qualificationBinding !== undefined) {
      for (const key of ["source_commit", "source_tree", "deployment_digest", "artifact_sha256", "run_id", "job_id"]) {
        if (value[key] !== qualificationBinding[key]) fail();
      }
    }
    if (value.details === null || typeof value.details !== "object" || Array.isArray(value.details)) fail();
    return Object.freeze({ ...value });
  } catch (error) {
    if (error instanceof CloudSignerKmsQualificationError) throw error;
    fail();
  }
}

function normalizeScenarioResult(value, binding, scenario, qualificationBinding) {
  const envelope = normalizeCloudSignerKmsProviderEvidence(value, { binding, scenario, qualificationBinding });
  const details = envelope.details;
  const keys = scenario === "provider_contract"
    ? ["algorithm", "public_key_fingerprint", "protocol_version", "signature_length", "status"]
    : scenario === "key_version_binding"
      ? ["key_id", "key_version", "lifecycle_version", "status"]
      : scenario === "rotation"
        ? ["drained", "new_key_version", "new_signing_allowed", "old_key_version", "old_signing_allowed", "old_verification_allowed", "status"]
      : scenario === "disable"
      ? ["key_version", "lifecycle_version", "provider_called_after_disable", "reserved_after_disable", "signing_allowed", "status", "verification_allowed"]
          : scenario === "non_exportability"
            ? ["export_attempted", "export_rejected", "exportable", "private_material_observed", "status"]
          : scenario === "lifecycle_fence"
            ? ["fenced", "provider_called_after_fence", "reserved", "status"]
            : scenario === "response_loss_reconciliation"
              ? ["blind_retries", "lookup_calls", "provider_calls", "reconciled", "status", "uncertain_transitions"]
              : ["signature_length", "status", "verified"];
  exactObject(details, keys);
  if (!STATUS.has(details.status) || details.status !== envelope.status) fail();
  if (scenario === "provider_contract" && (details.algorithm !== "ed25519" || details.protocol_version !== binding.protocol_version
    || details.signature_length !== 64 || details.public_key_fingerprint !== binding.public_key_fingerprint)) fail();
  if (scenario === "key_version_binding" && (details.key_id !== binding.key_id || typeof details.key_version !== "string" || details.key_version !== binding.key_version
    || !Number.isSafeInteger(details.lifecycle_version) || details.lifecycle_version < 1)) fail();
  if (scenario === "rotation") {
    if (typeof details.old_key_version !== "string" || !IDENTIFIER.test(details.old_key_version)
      || typeof details.new_key_version !== "string" || !IDENTIFIER.test(details.new_key_version)
      || details.new_key_version !== binding.key_version || details.old_key_version === details.new_key_version
      || typeof details.old_verification_allowed !== "boolean" || typeof details.old_signing_allowed !== "boolean"
      || typeof details.new_signing_allowed !== "boolean" || typeof details.drained !== "boolean") fail();
    if (details.status === "passed" && (details.old_verification_allowed !== true || details.old_signing_allowed !== false
      || details.new_signing_allowed !== true || details.drained !== true)) fail();
  }
  if (scenario === "disable") {
    if (details.key_version !== binding.key_version || !Number.isSafeInteger(details.lifecycle_version) || details.lifecycle_version < 1
      || typeof details.provider_called_after_disable !== "boolean" || typeof details.reserved_after_disable !== "boolean"
      || typeof details.signing_allowed !== "boolean" || typeof details.verification_allowed !== "boolean") fail();
    if (details.status === "passed" && (details.provider_called_after_disable !== false || details.reserved_after_disable !== false
      || details.signing_allowed !== false || details.verification_allowed !== true)) fail();
  }
  if (scenario === "non_exportability") {
    if (typeof details.export_attempted !== "boolean" || typeof details.export_rejected !== "boolean"
      || typeof details.exportable !== "boolean" || typeof details.private_material_observed !== "boolean") fail();
    if (details.status === "passed" && (details.export_attempted !== true || details.export_rejected !== true
      || details.exportable !== false || details.private_material_observed !== false)) fail();
  }
  if (scenario === "lifecycle_fence") {
    if (typeof details.reserved !== "boolean" || typeof details.fenced !== "boolean" || typeof details.provider_called_after_fence !== "boolean") fail();
    if (details.status === "passed" && (details.reserved !== true || details.fenced !== true || details.provider_called_after_fence !== false)) fail();
  }
  if (scenario === "response_loss_reconciliation" && (!nonNegative(details.provider_calls) || !nonNegative(details.lookup_calls)
    || !nonNegative(details.blind_retries) || !Number.isSafeInteger(details.uncertain_transitions) || details.uncertain_transitions < 1
    || typeof details.reconciled !== "boolean")) fail();
  if (scenario === "response_loss_reconciliation" && details.status === "passed"
    && (details.blind_retries !== 0 || details.lookup_calls < 1 || details.provider_calls < 1 || details.reconciled !== true)) fail();
  if (scenario === "canary_sign_verify" && (details.verified !== true || details.signature_length !== 64)) fail();
  const normalizedDetails = scenario === "provider_contract"
    ? { algorithm: details.algorithm, public_key_fingerprint: details.public_key_fingerprint, protocol_version: details.protocol_version, signature_length: details.signature_length, status: details.status }
      : scenario === "key_version_binding"
      ? { key_id: details.key_id, key_version: String(details.key_version), lifecycle_version: details.lifecycle_version, status: details.status }
      : scenario === "rotation"
        ? { drained: details.drained, new_key_version: details.new_key_version, new_signing_allowed: details.new_signing_allowed, old_key_version: details.old_key_version, old_signing_allowed: details.old_signing_allowed, old_verification_allowed: details.old_verification_allowed, status: details.status }
        : scenario === "disable"
          ? { key_version: details.key_version, lifecycle_version: details.lifecycle_version, provider_called_after_disable: details.provider_called_after_disable, reserved_after_disable: details.reserved_after_disable, signing_allowed: details.signing_allowed, status: details.status, verification_allowed: details.verification_allowed }
      : scenario === "non_exportability"
        ? { export_attempted: details.export_attempted, export_rejected: details.export_rejected, exportable: details.exportable, private_material_observed: details.private_material_observed, status: details.status }
          : scenario === "lifecycle_fence"
            ? { fenced: details.fenced, provider_called_after_fence: details.provider_called_after_fence, reserved: details.reserved, status: details.status }
            : scenario === "response_loss_reconciliation"
              ? { blind_retries: details.blind_retries, lookup_calls: details.lookup_calls, provider_calls: details.provider_calls, reconciled: details.reconciled, status: details.status, uncertain_transitions: details.uncertain_transitions }
              : { signature_length: details.signature_length, status: details.status, verified: details.verified };
  return Object.freeze({ purpose: binding.purpose, scenario, status: normalizedDetails.status, evidence: Object.freeze({ ...envelope, details: Object.freeze(normalizedDetails) }) });
}

function normalizeScenarioList(value, bindings, qualificationBinding) {
  if (!Array.isArray(value) || value.length !== bindings.length * CLOUD_SIGNER_KMS_SCENARIOS.length) fail();
  const result = value.map((item, index) => {
    const binding = bindings[Math.floor(index / CLOUD_SIGNER_KMS_SCENARIOS.length)];
    const scenario = CLOUD_SIGNER_KMS_SCENARIOS[index % CLOUD_SIGNER_KMS_SCENARIOS.length];
    exactObject(item, ["evidence", "purpose", "scenario", "status"]);
    if (item.purpose !== binding.purpose || item.scenario !== scenario) fail();
    const normalized = normalizeScenarioResult(item.evidence, binding, scenario, qualificationBinding);
    if (item.status !== normalized.status) fail();
    return normalized;
  });
  return Object.freeze(result);
}

function normalizePostgresEvidence(value) {
  exactObject(value, ["instances", "resilience", "status"]);
  if (value.status !== "passed" && value.status !== "failed" || !Array.isArray(value.instances) || value.instances.length !== 2) fail();
  const instances = value.instances.map((item) => {
    exactObject(item, ["instance_digest", "name", "status"]);
    if (typeof item.name !== "string" || !IDENTIFIER.test(item.name) || !DIGEST.test(item.instance_digest) || !STATUS.has(item.status)) fail();
    return Object.freeze({ ...item });
  });
  if (new Set(instances.map((item) => item.name)).size !== 2
    || (value.status === "passed" && instances.some((item) => item.status !== "passed"))) fail();
  const resilience = normalizePostgresResilience(value.resilience);
  if (value.status === "passed" && resilience.status !== "passed") fail();
  return Object.freeze({ status: value.status, instances: Object.freeze(instances), resilience });
}

function normalizePostgresResilience(value) {
  exactObject(value, ["blind_retries", "failover_recovered", "response_loss_reconciled", "restart_recovered", "single_commit", "status", "two_instance", "uncertain_state_durable"]);
  if (!STATUS.has(value.status) || !nonNegative(value.blind_retries)
    || typeof value.failover_recovered !== "boolean" || typeof value.response_loss_reconciled !== "boolean"
    || typeof value.restart_recovered !== "boolean" || typeof value.single_commit !== "boolean"
    || typeof value.two_instance !== "boolean" || typeof value.uncertain_state_durable !== "boolean") fail();
  if (value.status === "passed" && (value.blind_retries !== 0 || value.failover_recovered !== true
    || value.response_loss_reconciled !== true || value.restart_recovered !== true || value.single_commit !== true
    || value.two_instance !== true || value.uncertain_state_durable !== true)) fail();
  return Object.freeze({ ...value });
}

function assertIamMatrix(value) {
  if (value.length !== 64) fail();
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (item.caller_purpose !== CLOUD_SIGNER_KMS_PURPOSES[Math.floor(index / 8)]
      || item.key_purpose !== CLOUD_SIGNER_KMS_PURPOSES[index % 8]) fail();
  }
}

function expectedIamDecision(caller, target) { return caller === target ? "allow" : "deny"; }
function failureReason(iam, scenarios, postgres) {
  if (iam.some((item) => item.decision !== expectedIamDecision(item.caller_purpose, item.key_purpose))) return "iam_mismatch";
  if (scenarios.some((item) => item.scenario === "lifecycle_fence" && item.status !== "passed")) return "lifecycle_fenced";
  if (scenarios.some((item) => item.scenario === "response_loss_reconciliation" && item.status !== "passed")) return "reconciliation_uncertain";
  if (postgres.status !== "passed") return "postgres_qualification_failed";
  return "incomplete_run";
}
function notRunEvidence(startedAt, reason) {
  return Object.freeze({ schema_version: CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION, kind: CLOUD_SIGNER_KMS_QUALIFICATION_KIND, status: "not_run", qualified: false,
    reason, started_at: startedAt, completed_at: startedAt });
}
function failedEvidence(startedAt, reason, sourceCommit, sourceTree, deploymentDigest, artifactSha256, runId, jobId) {
  return Object.freeze({ schema_version: CLOUD_SIGNER_KMS_QUALIFICATION_SCHEMA_VERSION, kind: CLOUD_SIGNER_KMS_QUALIFICATION_KIND, status: "failed", qualified: false,
    reason, source_commit: typeof sourceCommit === "string" && SOURCE_COMMIT.test(sourceCommit) ? sourceCommit : "0".repeat(40),
    source_tree: typeof sourceTree === "string" && SOURCE_TREE.test(sourceTree) ? sourceTree : "0".repeat(40),
    deployment_digest: typeof deploymentDigest === "string" && DIGEST.test(deploymentDigest) ? deploymentDigest : "0".repeat(64),
    artifact_sha256: typeof artifactSha256 === "string" && DIGEST.test(artifactSha256) ? artifactSha256 : "0".repeat(64), execution: null, provider_identities: [],
    run_id: RUN_ID.test(String(runId ?? "")) ? String(runId) : "1", job_id: RUN_ID.test(String(jobId ?? "")) ? String(jobId) : "1",
    started_at: startedAt, completed_at: startedAt, purpose_bindings: [], iam_matrix: [], scenarios: [],
    postgres: { status: "failed", instances: [] } });
}
function safeReason(error) { return SAFE_REASONS.has(error?.code) ? error.code : (error?.code === "invalid_evidence" ? "invalid_provider_output" : "incomplete_run"); }
function invalidBindingReason({ sourceCommit, sourceTree, deploymentDigest, runId, jobId }) {
  if (typeof sourceCommit !== "string" || !SOURCE_COMMIT.test(sourceCommit)
    || typeof sourceTree !== "string" || !SOURCE_TREE.test(sourceTree)) return "invalid_source_binding";
  if (typeof deploymentDigest !== "string" || !DIGEST.test(deploymentDigest)) return "invalid_deployment_binding";
  if (!RUN_ID.test(String(runId ?? "")) || !RUN_ID.test(String(jobId ?? ""))) return "invalid_run_binding";
  return null;
}
function nonNegative(value) { return Number.isSafeInteger(value) && value >= 0; }
function timestamp(value) {
  const result = value instanceof Date ? value.toISOString() : value;
  if (typeof result !== "string" || !TIMESTAMP.test(result) || !Number.isFinite(Date.parse(result))) throw new CloudSignerKmsQualificationError(CLOUD_SIGNER_KMS_QUALIFICATION_ERROR_CODES.CONFIG);
  return result;
}
function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) fail();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
  }
}
function plainExactObject(value, keys) {
  try { exactObject(value, keys); return true; } catch { return false; }
}
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"); }
function fail() { throw new CloudSignerKmsQualificationError(CLOUD_SIGNER_KMS_QUALIFICATION_ERROR_CODES.INPUT); }

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const report = await runCloudSignerKmsQualification();
  process.stdout.write(`${canonicalCloudSignerKmsQualificationEvidence(report)}\n`);
  if (report.status !== "passed") process.exitCode = 1;
}
