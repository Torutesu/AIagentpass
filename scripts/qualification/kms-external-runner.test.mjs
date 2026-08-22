import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { identityAttestationNonce } from "./cloud-signer-kms.mjs";
import {
  identityBindingDigest,
  KMS_PROVIDER_IDENTITY_ATTESTATION_KIND,
  attestationSigningData,
  publicKeyFingerprint
} from "./kms-provider-identity-attestation.mjs";
import { KmsQualificationRunnerError, runExternalKmsQualification, verifyProviderIdentityAttestations } from "./run-kms-qualification.mjs";

function longRunningAttestationReport() {
  const startedAt = "2026-08-21T00:00:00.000Z";
  const completedAt = "2026-08-21T01:00:00.000Z";
  const qualificationBinding = {
    source_commit: "a".repeat(40), source_tree: "b".repeat(40), deployment_digest: "c".repeat(64),
    artifact_sha256: "d".repeat(64), run_id: "42", job_id: "1001"
  };
  const targets = {
    "aws-kms": { account_or_project: "123456789012", identity: "aws-role-agentpass", identity_fingerprint: "1".repeat(64), region: "us-east-1", resource_id: "arn:aws:kms:us-east-1:123456789012:key/signing" },
    "gcp-cloud-kms": { account_or_project: "agentpass", identity: "gcp-service-agentpass", identity_fingerprint: "2".repeat(64), region: "global", resource_id: "projects/agentpass/locations/global/keyRings/signing/cryptoKeys/signing/cryptoKeyVersions/1" }
  };
  const trust = {};
  const providerIdentities = [];
  for (const [provider, target] of Object.entries(targets)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const keyId = `${provider}-attestor-v1`;
    trust[provider] = {
      key_id: keyId,
      public_key_der_base64url: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
      public_key_fingerprint: publicKeyFingerprint(publicKey)
    };
    const resourceIds = [target.resource_id];
    const attestation = {
      schema_version: 1,
      kind: KMS_PROVIDER_IDENTITY_ATTESTATION_KIND,
      provider,
      account_or_project: target.account_or_project,
      identity: target.identity,
      identity_fingerprint: target.identity_fingerprint,
      region: target.region,
      resource_ids: resourceIds,
      challenge: {
        nonce: identityAttestationNonce(provider, qualificationBinding),
        binding_digest: identityBindingDigest({ ...qualificationBinding, provider, ...target, resource_ids: resourceIds }),
        issued_at: startedAt,
        expires_at: "2026-08-21T00:05:00.000Z"
      },
      provider_claims: { identity_document_digest: "5".repeat(64), request_digest: "6".repeat(64), response_digest: "7".repeat(64) },
      signature_algorithm: "ed25519",
      attestor_key_id: keyId,
      attestor_public_key_fingerprint: publicKeyFingerprint(publicKey),
      signature_base64url: "placeholder"
    };
    attestation.signature_base64url = crypto.sign(null, attestationSigningData(attestation), privateKey).toString("base64url");
    providerIdentities.push({
      account_or_project: target.account_or_project,
      authenticated: true,
      challenge_digest: "8".repeat(64),
      credential_source: provider === "aws-kms" ? "aws_workload_identity" : "gcp_workload_identity",
      identity: target.identity,
      identity_fingerprint: target.identity_fingerprint,
      observed_at: startedAt,
      proof_kind: provider === "aws-kms" ? "aws_sts_get_caller_identity" : "gcp_iam_credentials_principal",
      provider,
      region: target.region,
      response_digest: "7".repeat(64),
      attestation
    });
  }
  return {
    report: { ...qualificationBinding, started_at: startedAt, completed_at: completedAt, provider_identities: providerIdentities, purpose_bindings: Object.values(targets).map((target, index) => ({ provider: index === 0 ? "aws-kms" : "gcp-cloud-kms", provider_resource_id: target.resource_id })) },
    expectedBindings: Object.fromEntries(Object.entries(targets).map(([provider, target]) => [provider, { provider, provider_resource_id: target.resource_id }])),
    env: { AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS: JSON.stringify(trust) }
  };
}

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

test("external attestation verification accepts a completed report after the five-minute TTL", () => {
  const fixture = longRunningAttestationReport();
  assert.doesNotThrow(() => verifyProviderIdentityAttestations(fixture.report, fixture.expectedBindings, fixture.env));
});
