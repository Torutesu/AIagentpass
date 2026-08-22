import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(".github/workflows/cloud-production-qualification.yml", "utf8");

test("cloud production qualification requires signed operations evidence inputs", () => {
  assert.match(workflow, /operations_evidence_url:/u);
  assert.match(workflow, /candidate_id:/u);
  assert.match(workflow, /AGENTPASS_OPERATIONS_EVIDENCE_PUBLIC_KEY_PEM/u);
  assert.match(workflow, /AGENTPASS_OPERATIONS_EVIDENCE_KEY_FINGERPRINT/u);
  assert.match(workflow, /verify-operations-evidence-bundle\.mjs verify/u);
  assert.match(workflow, /evidence_count == 5/u);
  assert.match(workflow, /operations-evidence\.tar/u);
  assert.match(workflow, /operations evidence archive exceeds the size limit/u);
});

test("workflow keeps the operations evidence boundary fail-closed", () => {
  assert.match(workflow, /operations evidence URL must use HTTPS/u);
  assert.match(workflow, /operations evidence public key is required/u);
  assert.match(workflow, /tar --extract --file/u);
  assert.match(workflow, /--no-same-owner --no-same-permissions/u);
  assert.match(workflow, /archive_entries/u);
  assert.match(workflow, /unexpected entry count/u);
  assert.match(workflow, /expected_archive_entries=\$'alert_delivery\.json\\nbackup_restore_pitr\.json/u);
  assert.match(workflow, /sort -u/u);
  assert.match(workflow, /! -L "\$target"/u);
  assert.match(workflow, /stat -c '%h'/u);
  assert.match(workflow, /status == "verified"/u);
  assert.match(workflow, /operations-evidence\.tar\.sha256/u);
});

test("workflow requires the Cloud signer v2 evidence and every immutable binding", () => {
  for (const input of [
    "cloud_signer_qualification_url",
    "kms_artifact_sha256",
    "kms_qualification_run_id",
    "kms_qualification_run_attempt",
    "kms_qualification_job_id"
  ]) assert.match(workflow, new RegExp(`${input}:[\\s\\S]*?required: true`, "u"));
  assert.match(workflow, /KMS_DEPLOYMENT_DIGEST: \$\{\{ vars\.AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST \}\}/u);
  assert.match(workflow, /KMS_EXPECTED_BINDINGS: \$\{\{ vars\.AGENTPASS_KMS_QUALIFICATION_EXPECTED_BINDINGS \}\}/u);
  assert.match(workflow, /KMS_SOURCE_TREE=%s/u);
  assert.match(workflow, /git rev-parse 'HEAD\^\{tree\}'/u);
  assert.match(workflow, /KMS_ARTIFACT_SHA256.*\^\[0-9a-f\]\{64\}/u);
  assert.match(workflow, /KMS_QUALIFICATION_RUN_ID.*\^\[1-9\]\[0-9\]\{0,19\}/u);
  assert.match(workflow, /KMS_QUALIFICATION_JOB_ID.*\^\[1-9\]\[0-9\]\{0,19\}/u);
});

test("workflow independently binds the external run, workflow, source, attempt, and kms job", () => {
  assert.match(workflow, /actions: read/u);
  assert.match(workflow, /actions\/runs\/\$KMS_QUALIFICATION_RUN_ID/u);
  assert.match(workflow, /actions\/runs\/\$KMS_QUALIFICATION_RUN_ID\/artifacts/u);
  assert.match(workflow, /external-kms-qualification-\$\{EXPECTED_COMMIT\}-\$\{KMS_QUALIFICATION_RUN_ID\}-\$\{KMS_QUALIFICATION_RUN_ATTEMPT\}/u);
  assert.match(workflow, /KMS_EVIDENCE_ARTIFACT_DIGEST/u);
  assert.match(workflow, /cmp -s .*cloud-signer-qualification\.json/u);
  assert.match(workflow, /Cloud signer qualification URL is not bound to the selected GitHub artifact/u);
  assert.match(workflow, /External qualification runners/u);
  assert.match(workflow, /external-qualification-runners\.yml/u);
  assert.match(workflow, /\.event == "workflow_dispatch"/u);
  assert.match(workflow, /\.head_sha == \$commit/u);
  assert.match(workflow, /\.run_attempt\|tostring\) == \$attempt/u);
  assert.match(workflow, /\.name == "kms"/u);
  assert.match(workflow, /\.run_id\|tostring\) == \$run/u);
  assert.match(workflow, /\.conclusion == "success"/u);
});

test("workflow executes the canonical Cloud signer gate and cryptographically verifies provider identity attestations", () => {
  assert.match(workflow, /ci-preflight\.mjs kms-qualification/u);
  assert.match(workflow, /KMS_DEPLOYMENT_DIGEST[\s\S]*?KMS_ARTIFACT_SHA256[\s\S]*?KMS_QUALIFICATION_RUN_ID[\s\S]*?KMS_QUALIFICATION_JOB_ID/u);
  assert.match(workflow, /verifyCloudSignerKmsQualificationEvidence/u);
  assert.match(workflow, /requireProviderIdentityAttestation: true/u);
  assert.match(workflow, /normalizeKmsProviderIdentityAttestorTrustInputs/u);
  assert.match(workflow, /verifyKmsProviderIdentityAttestation/u);
  assert.match(workflow, /provider identity attestor trust is not canonical JSON/u);
  assert.match(workflow, /identityAttestationNonce/u);
  assert.match(workflow, /identityBindingDigest/u);
  assert.match(workflow, /expected provider target binding is mismatched/u);
  assert.match(workflow, /expected provider identity is mismatched/u);
  assert.match(workflow, /Cloud signer evidence is not canonical JSON/u);
  assert.match(workflow, /canonicalJson\(value\)\}\\n/u);
  assert.match(workflow, /cloud-signer-qualification-canonical\.json/u);
  assert.match(workflow, /Cloud signer qualification is not passed/u);
  assert.match(workflow, /evidence\.status === 'not_run'/u);
  assert.match(workflow, /qualification_run_attempt !== expectedAttempt/u);
});

test("workflow enforces independent signing keys and preserves the verified binding in the uploaded artifact", () => {
  assert.match(workflow, /KMS_IDENTITY_ATTESTATION_TRUST: \$\{\{ secrets\.AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST \}\}/u);
  assert.match(workflow, /deployment and KMS qualification keys must be independent/u);
  assert.match(workflow, /provider identity attestor key must be independent/u);
  assert.match(workflow, /cloud-signer-identity-verification\.json/u);
  assert.match(workflow, /schema_version:2,source_commit:\$commit,source_tree:\$tree/u);
  assert.match(workflow, /deployment_digest:\$deployment,artifact_sha256:\$artifact/u);
  assert.match(workflow, /qualification_run_id:\$run,qualification_run_attempt:\$attempt,qualification_job_id:\$job/u);
});
