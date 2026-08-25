import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../../apps/cloud-api/src/postgres/schema-head.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../../../apps/cloud-api/src/signer-purpose-registry.mjs";
import {
  CLOUD_SIGNER_KMS_IAM_ATTESTATION_KIND, CLOUD_SIGNER_KMS_PURPOSES,
  iamAttestationSigningData,
  identityChallengeDigest,
  runCloudSignerKmsQualification
} from "../../qualification/cloud-signer-kms.mjs";
import { KMS_PROVIDER_IDENTITY_ATTESTATION_KIND, attestationSigningData, publicKeyFingerprint } from "../../qualification/kms-provider-identity-attestation.mjs";
import {
  PLATFORM_AUTH_QUALIFICATION_KIND,
  PLATFORM_AUTH_SCENARIO_CHECKS,
  PLATFORM_AUTH_SCENARIOS,
  platformAuthScenarioEvidenceSHA256
} from "../../qualification/platform-auth.mjs";
import { EXTERNAL_QUALIFICATION_ARTIFACTS, verifyExternalQualificationArtifacts } from "./verify-external-artifact-provenance.mjs";
import { postgresControllerSigningData } from "../../qualification/aggregate-postgres-external.mjs";

const repository = "Torutesu/AIagentpass";
const sourceCommit = "a".repeat(40);
const sourceTree = "b".repeat(40);
const runId = "303";
const runAttempt = "2";
const canonicalRunId = "101";
const canonicalRunAttempt = "1";
const releaseArtifactSha256 = "c".repeat(64);
const CONTROLLER_KEYS = generateKeyPairSync("ed25519");
const CONTROLLER_DER = CONTROLLER_KEYS.publicKey.export({ type: "spki", format: "der" });
const CONTROLLER_FINGERPRINT = `SHA256:${createHash("sha256").update(CONTROLLER_DER).digest("base64url")}`;

function kmsBinding(name) {
  const expected = SIGNER_PURPOSE_REGISTRY[name];
  const index = CLOUD_SIGNER_KMS_PURPOSES.indexOf(name) + 1;
  const provider = index % 2 === 0 ? "gcp-cloud-kms" : "aws-kms";
  return {
    algorithm: "ed25519", domain: expected.domain, hosted_status: expected.hosted_status,
    key_id: `${name}-kms-key`, key_version: String(index), name, provider,
    provider_resource_id: provider === "gcp-cloud-kms"
      ? `projects/agentpass/locations/global/keyRings/${name}/cryptoKeys/${name}-kms-key/cryptoKeyVersions/${index}`
      : `arn:aws:kms:us-east-1:123456789012:key/${name}-kms-key`,
    public_key_fingerprint: (index.toString(16) + "b").repeat(64).slice(0, 64),
    protocol_version: expected.protocol_version, purpose: expected.purpose, registry_version: 1,
    signing_version: expected.signing_version, version: 1
  };
}

async function validKmsEvidence() {
  const attestors = Object.fromEntries(["aws-kms", "gcp-cloud-kms"].map((provider) => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return [provider, { privateKey, publicKey, key_id: `${provider}-attestor`, fingerprint: publicKeyFingerprint(publicKey) }];
  }));
  const expectedProviderBindings = Object.fromEntries(CLOUD_SIGNER_KMS_PURPOSES.map((name) => {
    const binding = kmsBinding(name);
    const identity = binding.provider === "aws-kms"
      ? { account_or_project: "123456789012", identity: "aws-role", identity_fingerprint: "1".repeat(64), region: "us-east-1" }
      : { account_or_project: "agentpass", identity: "gcp-service", identity_fingerprint: "2".repeat(64), region: "global" };
    return [name, { ...identity, provider: binding.provider, provider_resource_id: binding.provider_resource_id, key_id: binding.key_id, key_version: binding.key_version, public_key_fingerprint: binding.public_key_fingerprint }];
  }));
  const sourceCommit = "a".repeat(40);
  const sourceTree = "b".repeat(40);
  const deploymentDigest = "d".repeat(64);
  const jobId = "401";
  const startedAt = "2026-08-21T00:00:00.000Z";
  const env = {
    AGENTPASS_KMS_QUALIFICATION_ENABLED: "true",
    AGENTPASS_KMS_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: "protected-kms-runner",
    AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MODE: "multi_provider_workload_identity",
    AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_SOURCE: "multi_provider_workload_identity",
    AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_ISSUED_AT: "2026-08-21T00:00:00.000Z",
    AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_EXPIRES_AT: "2026-08-21T00:04:00.000Z",
    AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MAX_TTL_SECONDS: "300",
    AGENTPASS_KMS_QUALIFICATION_EXPECTED_BINDINGS: JSON.stringify(expectedProviderBindings),
    AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS: JSON.stringify(Object.fromEntries(Object.entries(attestors).map(([provider, item]) => [provider, {
      key_id: item.key_id,
      public_key_der_base64url: item.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
      public_key_fingerprint: item.fingerprint
    }]))),
    AGENTPASS_KMS_QUALIFICATION_IAM_ATTESTATION: JSON.stringify(Object.fromEntries(["aws-kms", "gcp-cloud-kms"].map((provider) => {
      const expected = Object.values(expectedProviderBindings).filter((item) => item.provider === provider);
      const first = expected[0];
      const attestation = {
        artifact_sha256: releaseArtifactSha256,
        attestor_key_id: attestors[provider].key_id,
        attestor_public_key_fingerprint: attestors[provider].fingerprint,
        deployment_digest: deploymentDigest,
        expires_at: "2026-08-21T00:05:00.000Z",
        identity: first.identity,
        identity_fingerprint: first.identity_fingerprint,
        issued_at: startedAt,
        kind: CLOUD_SIGNER_KMS_IAM_ATTESTATION_KIND,
        policy_digest: `${provider === "aws-kms" ? "7" : "8"}`.repeat(64),
        provider,
        account_or_project: first.account_or_project,
        region: first.region,
        resource_ids: expected.map((item) => item.provider_resource_id).sort(),
        run_id: runId,
        job_id: jobId,
        schema_version: 1,
        signature_base64url: "placeholder",
        source_commit: sourceCommit,
        source_tree: sourceTree
      };
      attestation.signature_base64url = sign(null, iamAttestationSigningData(attestation), attestors[provider].privateKey).toString("base64url");
      return [provider, attestation];
    })))
  };
  const qualificationBinding = { source_commit: sourceCommit, source_tree: sourceTree, deployment_digest: deploymentDigest, artifact_sha256: releaseArtifactSha256, run_id: runId, job_id: jobId };
  const identities = {
    "aws-kms": { account_or_project: "123456789012", credential_source: "aws_workload_identity", identity: "aws-role", identity_fingerprint: "1".repeat(64), region: "us-east-1", response_digest: "3".repeat(64), proof_kind: "aws_sts_get_caller_identity" },
    "gcp-cloud-kms": { account_or_project: "agentpass", credential_source: "gcp_workload_identity", identity: "gcp-service", identity_fingerprint: "2".repeat(64), region: "global", response_digest: "4".repeat(64), proof_kind: "gcp_iam_credentials_principal" }
  };
  const identityProbe = async ({ binding, identity_challenges: challenges }) => challenges.map((challenge) => {
    const info = identities[challenge.provider];
    const attestation = {
      schema_version: 1, kind: KMS_PROVIDER_IDENTITY_ATTESTATION_KIND, provider: challenge.provider,
      account_or_project: info.account_or_project, identity: info.identity, identity_fingerprint: info.identity_fingerprint,
      region: info.region, resource_ids: challenge.resource_ids,
      challenge: { nonce: challenge.nonce, binding_digest: challenge.binding_digest, issued_at: challenge.issued_at, expires_at: challenge.expires_at },
      provider_claims: { identity_document_digest: "5".repeat(64), request_digest: "6".repeat(64), response_digest: info.response_digest },
      signature_algorithm: "ed25519", attestor_key_id: attestors[challenge.provider].key_id,
      attestor_public_key_fingerprint: attestors[challenge.provider].fingerprint, signature_base64url: ""
    };
    attestation.signature_base64url = sign(null, attestationSigningData(attestation), attestors[challenge.provider].privateKey).toString("base64url");
    return { ...info, authenticated: true, challenge_digest: identityChallengeDigest(challenge.provider, binding), observed_at: challenge.issued_at, provider: challenge.provider, attestation };
  });
  const purposeFactory = async ({ name }) => ({ binding: kmsBinding(name), handle: { name } });
  const iamProbe = async ({ caller_purpose, key_purpose }) => ({ decision: caller_purpose === key_purpose ? "allow" : "deny" });
  const scenarioProbe = async ({ expected, scenario }) => {
    const details = scenario === "provider_contract"
      ? { algorithm: "ed25519", public_key_fingerprint: expected.public_key_fingerprint, protocol_version: expected.protocol_version, signature_length: 64, status: "passed" }
      : scenario === "key_version_binding"
        ? { key_id: expected.key_id, key_version: expected.key_version, lifecycle_version: 1, status: "passed" }
        : scenario === "rotation"
          ? { drained: true, new_key_version: expected.key_version, new_signing_allowed: true, old_key_version: `${expected.key_version}-old`, old_signing_allowed: false, old_verification_allowed: true, status: "passed" }
          : scenario === "disable"
            ? { key_version: expected.key_version, lifecycle_version: 2, provider_called_after_disable: false, reserved_after_disable: false, signing_allowed: false, status: "passed", verification_allowed: true }
            : scenario === "non_exportability"
              ? { export_attempted: true, export_rejected: true, exportable: false, private_material_observed: false, status: "passed" }
              : scenario === "lifecycle_fence"
                ? { fenced: true, provider_called_after_fence: false, reserved: true, status: "passed" }
                : scenario === "response_loss_reconciliation"
                  ? { blind_retries: 0, lookup_calls: 1, provider_calls: 1, reconciled: true, status: "passed", uncertain_transitions: 1 }
                  : { signature_length: 64, status: "passed", verified: true };
    return { schema_version: 1, kind: "agentpass-cloud-signer-kms-provider-evidence", source_commit: sourceCommit, source_tree: sourceTree, deployment_digest: deploymentDigest, artifact_sha256: releaseArtifactSha256, run_id: runId, job_id: jobId, purpose: expected.purpose, key_id: expected.key_id, key_version: expected.key_version, scenario, status: "passed", details };
  };
  const postgresProbe = async () => ({ status: "passed", instances: [{ name: "pg16", instance_digest: "7".repeat(64), status: "passed" }, { name: "pg17", instance_digest: "8".repeat(64), status: "passed" }], resilience: { blind_retries: 0, failover_recovered: true, response_loss_reconciled: true, restart_recovered: true, single_commit: true, status: "passed", two_instance: true, uncertain_state_durable: true } });
  return runCloudSignerKmsQualification({ env, now: () => new Date(startedAt), sourceCommit, sourceTree, deploymentDigest, artifactSha256: releaseArtifactSha256, runId, jobId, identityProbe, purposeFactory, iamProbe, scenarioProbe, postgresProbe });
}

const VALID_KMS_EVIDENCE = await validKmsEvidence();

function validWebAuthnEvidence(jobId) {
  const checks = ["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"].map((check_id) => {
    const item = { check_id, status: "passed", expected: { type: "boolean", value: true }, observed: { type: "boolean", value: true } };
    return { ...item, evidence_sha256: createHash("sha256").update(canonicalJson(item), "utf8").digest("hex") };
  });
  return {
    schema_version: 1, kind: "agentpass-webauthn-agent-unattended-e2e", status: "passed", qualified: true, reason: null,
    execution: {
      kind: "external_runner", real_execution: true, runner_id: "protected-webauthn-runner", run_id: runId, run_attempt: runAttempt, job_id: jobId,
      source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, ci_run_id: canonicalRunId, ci_run_attempt: canonicalRunAttempt,
      qualification_run_id: runId, qualification_run_attempt: runAttempt, qualification_job_id: jobId, started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z",
      environment: { kind: "webauthn", identity: "protected-webauthn-deployment", authenticator: "platform", origin: "https://console.agentpass.example", rp_id: "agentpass.example", instance_ids: ["web-01", "web-02"] }
    },
    required_checks: checks.map((item) => item.check_id), checks
  };
}

function platformAuthEvidence(jobId) {
  const deploymentDigests = { primary: "d".repeat(64), secondary: "e".repeat(64) };
  const instance = (name) => ({
    name,
    source_commit: sourceCommit,
    deployment_digest: deploymentDigests[name],
    scenarios: PLATFORM_AUTH_SCENARIOS.map((scenario, index) => {
      if (!PLATFORM_AUTH_SCENARIO_CHECKS[scenario]) return { scenario, status: "passed", evidence_sha256: `${index + 1}`.repeat(64).slice(0, 64) };
      const evidence = {
        schema_version: 1,
        kind: `${PLATFORM_AUTH_QUALIFICATION_KIND}-scenario`,
        scenario,
        status: "passed",
        instance: name,
        source_commit: sourceCommit,
        source_tree: sourceTree,
        deployment_digest: deploymentDigests[name],
        run_id: runId,
        job_id: jobId,
        started_at: "2026-08-21T00:00:00.000Z",
        completed_at: "2026-08-21T00:01:00.000Z",
        checks: PLATFORM_AUTH_SCENARIO_CHECKS[scenario].map((check_id) => ({
          check_id,
          status: "passed",
          expected: { type: "boolean", value: true },
          result: { type: "boolean", value: true }
        }))
      };
      return { scenario, status: "passed", evidence, evidence_sha256: platformAuthScenarioEvidenceSHA256(evidence) };
    })
  });
  return {
    schema_version: 1,
    kind: PLATFORM_AUTH_QUALIFICATION_KIND,
    status: "passed",
    qualified: true,
    reason: null,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    run_id: runId,
    job_id: jobId,
    started_at: "2026-08-21T00:00:00.000Z",
    completed_at: "2026-08-21T00:01:00.000Z",
    deployment_digests: deploymentDigests,
    instances: [instance("primary"), instance("secondary")],
    ci_run_id: canonicalRunId,
    ci_run_attempt: canonicalRunAttempt,
    qualification_run_id: runId,
    qualification_run_attempt: runAttempt,
    qualification_job_id: jobId,
    execution: {
      kind: "external_runner",
      real_execution: true,
      runner_id: "protected-platform-auth",
      run_id: runId,
      job_id: jobId,
      run_attempt: runAttempt,
      source_commit: sourceCommit,
      source_tree: sourceTree,
      ci_run_id: canonicalRunId,
      ci_run_attempt: canonicalRunAttempt,
      qualification_run_id: runId,
      qualification_run_attempt: runAttempt,
      qualification_job_id: jobId,
      started_at: "2026-08-21T00:00:00.000Z",
      completed_at: "2026-08-21T00:01:00.000Z",
      environment: { kind: "platform_auth", identity: "platform-auth-prod" }
    }
  };
}

function postgresChild(job, major, jobId) {
  const checks = [
    ["postgresql_version", major, major],
    ["migration_contract", "passed", "passed"],
    ["role_rls_boundary", "passed", "passed"],
    ["concurrency_rollback", "passed", "passed"]
  ];
  return {
    schema_version: 1, kind: "agentpass-postgresql-external-qualification", status: "passed", qualified: true, reason: null,
    source_commit: sourceCommit, source_tree: sourceTree, run_id: runId, run_attempt: runAttempt, job_id: jobId,
    ci_run_id: canonicalRunId, ci_run_attempt: canonicalRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt,
    qualification_job_id: jobId, artifact_sha256: releaseArtifactSha256, postgres_major: major,
    migration_artifact_sha256: "d".repeat(64), c3_evidence_sha256: "e".repeat(64), c3_server_version: `${major}.4`, c3_database_name: "agentpass", c3_server_port: 5432,
    c3_schema_head: POSTGRES_SCHEMA_HEAD.version, c3_migration_checksum: "d".repeat(64), backup_pitr_evidence_sha256: "f".repeat(64),
    c3_check_statuses: { migration_checksum: "passed", schema_objects: "passed", catalog_constraints_validated: "passed", role_privileges_and_ownership: "passed", rls_policy_catalog: "passed", cross_role_privilege_boundary: "passed", generation_contention_single_winner: "passed", transaction_rollback: "passed" },
    execution: { kind: "external_runner", real_execution: true, runner_id: `protected-postgresql-${major}`, environment: { kind: "postgresql", identity: `pg-${major}` } },
    checks: checks.map(([check_id, expected, observed]) => ({ check_id, status: "passed", expected: { type: "string", value: expected }, observed: { type: "string", value: observed }, evidence_sha256: "f".repeat(64) })),
    started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z"
  };
}

function postgresGate(jobId, bundleDigest) {
  const checkIds = ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"];
  const controller = {
    kind: "external_qualification_controller",
    controller_id: "postgres-gate-controller",
    runner_id: "protected-postgresql",
    environment_id: "pg-gate",
    run_id: runId,
    run_attempt: runAttempt,
    job_id: jobId,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    release_artifact_sha256: releaseArtifactSha256,
    artifact_sha256: bundleDigest,
    bundle_artifact_sha256: bundleDigest,
    child_evidence_sha256: { postgres_16: "1".repeat(64), postgres_17: "2".repeat(64) },
    signature: { algorithm: "ed25519", public_key_der_base64url: CONTROLLER_DER.toString("base64url"), public_key_fingerprint: CONTROLLER_FINGERPRINT, value: "" }
  };
  controller.signature.value = sign(null, postgresControllerSigningData(controller), CONTROLLER_KEYS.privateKey).toString("base64url");
  return {
    status: "passed", qualified: true, reason: null,
    execution: {
      kind: "external_runner", real_execution: true, runner_id: "protected-postgresql", run_id: runId, run_attempt: runAttempt, job_id: jobId,
      source_commit: sourceCommit, source_tree: sourceTree, release_artifact_sha256: releaseArtifactSha256, artifact_sha256: bundleDigest,
      ci_run_id: canonicalRunId, ci_run_attempt: canonicalRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt,
      qualification_job_id: jobId, qualification_job_name: "postgres-gate", started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z",
      environment: { kind: "postgresql", identity: "pg-gate" }
    },
    required_checks: checkIds,
    checks: checkIds.map((check_id) => ({ check_id, status: "passed" })),
    backup_pitr_evidence: { postgres_16_sha256: "f".repeat(64), postgres_17_sha256: "f".repeat(64), bundle_sha256: "f".repeat(64) },
    readiness: { status: "ready", migration_head: POSTGRES_SCHEMA_HEAD.version, catalog_constraints_validated: true, role_boundary_verified: true },
    controller
  };
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-external-provenance-"));
  const archives = path.join(root, "archives");
  fs.mkdirSync(archives, { mode: 0o700 });
  const run = {
    id: Number(runId),
    run_attempt: Number(runAttempt),
    name: "External qualification runners",
    path: ".github/workflows/external-qualification-runners.yml",
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: sourceCommit,
    status: "completed",
    conclusion: "success",
    repository: { id: 1, full_name: repository },
    head_repository: { id: 1, full_name: repository }
  };
  const canonicalRun = {
    id: Number(canonicalRunId),
    run_attempt: Number(canonicalRunAttempt),
    name: "CI",
    path: ".github/workflows/ci.yml",
    event: "push",
    head_branch: "main",
    head_sha: sourceCommit,
    status: "completed",
    conclusion: "success",
    repository: { id: 1, full_name: repository },
    head_repository: { id: 1, full_name: repository }
  };
  const jobs = ["validate", ...EXTERNAL_QUALIFICATION_ARTIFACTS.map(({ job }) => job), "external-qualification-provenance"].map((name, index) => ({
    id: String(400 + index),
    name,
    run_id: Number(runId),
    run_attempt: Number(runAttempt),
    head_sha: sourceCommit,
    status: name === "external-qualification-provenance" ? "in_progress" : "completed",
    conclusion: name === "external-qualification-provenance" ? null : "success",
    workflow_name: "External qualification runners"
  }));
  const artifacts = EXTERNAL_QUALIFICATION_ARTIFACTS.map(({ prefix, job }, index) => {
    const name = `${prefix}-${sourceCommit}-${runId}-${runAttempt}`;
    const evidencePath = path.join(root, `${job}.json`);
    const jobId = String(400 + 1 + index);
    const evidence = job === "postgres-authority-16"
      ? postgresChild(job, "16", jobId)
      : job === "postgres-authority-17"
        ? postgresChild(job, "17", jobId)
        : job === "postgres-gate"
          ? postgresGate(jobId, "0".repeat(64))
          : job === "kms"
            ? { ...structuredClone(VALID_KMS_EVIDENCE), run_id: runId, job_id: jobId, ci_run_id: canonicalRunId, ci_run_attempt: canonicalRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt, qualification_job_id: jobId }
          : job === "webauthn"
              ? validWebAuthnEvidence(jobId)
              : platformAuthEvidence(jobId);
    if (job === "postgres-gate") {
      const bundlePath = path.join(root, "input", "children.bundle");
      fs.mkdirSync(path.dirname(bundlePath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(bundlePath, "child bundle\n", { mode: 0o600 });
      evidence.execution.artifact_sha256 = createHash("sha256").update(fs.readFileSync(bundlePath)).digest("hex");
      evidence.controller.artifact_sha256 = evidence.execution.artifact_sha256;
      evidence.controller.bundle_artifact_sha256 = evidence.execution.artifact_sha256;
      evidence.controller.signature.value = sign(null, postgresControllerSigningData(evidence.controller), CONTROLLER_KEYS.privateKey).toString("base64url");
      fs.writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
      execFileSync("zip", ["-q", path.join(archives, `${name}.zip`), path.basename(evidencePath), "input/children.bundle"], { cwd: root });
    } else {
      fs.writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
      execFileSync("zip", ["-q", "-j", path.join(archives, `${name}.zip`), evidencePath]);
    }
    const bytes = fs.readFileSync(path.join(archives, `${name}.zip`));
    const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    return {
      id: 500 + index,
      name,
      digest,
      expired: false,
      workflow_run: { id: Number(runId), head_sha: sourceCommit, run_attempt: Number(runAttempt) }
    };
  });
  return { root, archives, run, canonicalRun, jobs: { total_count: jobs.length, jobs }, artifacts: { total_count: artifacts.length, artifacts } };
}

test("verifies exact external run/jobs, source-bound artifact names, and GitHub archive digests", () => {
  const value = fixture();
  const result = verifyExternalQualificationArtifacts({
    ...value,
    canonicalRun: value.canonicalRun,
    repository,
    sourceCommit,
    sourceTree,
    releaseArtifactSha256,
    runId,
    runAttempt,
    canonicalRunId,
    canonicalRunAttempt,
    archiveDirectory: value.archives
  });
  assert.equal(result.kind, "agentpass-external-qualification-artifact-provenance");
  assert.equal(result.artifacts.length, 6);
  assert.equal(result.artifacts[0].source_tree, sourceTree);
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("rejects a selected-source substitution, incomplete job inventory, or archive tampering", () => {
  const value = fixture();
  const wrongSource = structuredClone(value);
  wrongSource.artifacts.artifacts[0].name = wrongSource.artifacts.artifacts[0].name.replace(sourceCommit, "c".repeat(40));
  assert.throws(() => verifyExternalQualificationArtifacts({ ...wrongSource, canonicalRun: wrongSource.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: value.archives }), /missing or duplicated/u);

  const missingJob = fixture();
  missingJob.jobs.jobs.pop();
  missingJob.jobs.total_count -= 1;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...missingJob, canonicalRun: missingJob.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: missingJob.archives }), /job inventory/u);

  const tampered = fixture();
  const first = tampered.artifacts.artifacts[0];
  fs.writeFileSync(path.join(tampered.archives, `${first.name}.zip`), "tampered\n", { mode: 0o600 });
  assert.throws(() => verifyExternalQualificationArtifacts({ ...tampered, canonicalRun: tampered.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: tampered.archives }), /archive digest mismatch/u);
});

test("rejects canonical CI run substitution and evidence cross-run binding", () => {
  const wrongCanonical = fixture();
  wrongCanonical.canonicalRun.head_sha = "c".repeat(40);
  assert.throws(() => verifyExternalQualificationArtifacts({ ...wrongCanonical, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: wrongCanonical.archives }), /canonical CI workflow run identity/u);

  const wrongEvidence = fixture();
  const first = wrongEvidence.artifacts.artifacts[0];
  const archivePath = path.join(wrongEvidence.archives, `${first.name}.zip`);
  const evidencePath = path.join(wrongEvidence.root, "wrong-evidence.json");
  fs.writeFileSync(evidencePath, JSON.stringify({
    repository,
    source_commit: sourceCommit,
    qualification_run_id: runId,
    qualification_run_attempt: runAttempt,
    qualification_job_id: "401",
    qualification_job_name: "kms",
    ci_run_id: "999",
    ci_run_attempt: canonicalRunAttempt
  }), { mode: 0o600 });
  execFileSync("zip", ["-q", "-j", "-FS", archivePath, evidencePath]);
  const bytes = fs.readFileSync(archivePath);
  wrongEvidence.artifacts.artifacts[0].digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...wrongEvidence, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: wrongEvidence.archives }), /canonical CI run binding/u);
});

test("revalidates KMS and WebAuthn semantics and requires the independent release artifact binding", () => {
  const kms = fixture();
  const kmsArtifact = kms.artifacts.artifacts.find((item) => item.name.startsWith("external-kms-qualification-"));
  const kmsEvidencePath = path.join(kms.root, "kms.json");
  fs.writeFileSync(kmsEvidencePath, JSON.stringify({ repository, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: runId, run_attempt: runAttempt, job_id: "401", ci_run_id: canonicalRunId, ci_run_attempt: canonicalRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt, qualification_job_id: "401", status: "not_run", qualified: false }), { mode: 0o600 });
  const kmsArchivePath = path.join(kms.archives, `${kmsArtifact.name}.zip`);
  fs.rmSync(kmsArchivePath);
  execFileSync("zip", ["-q", "-j", kmsArchivePath, kmsEvidencePath]);
  kmsArtifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(kmsArchivePath)).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...kms, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: kms.archives }), /KMS qualification/u);

  const webauthn = fixture();
  const webauthnArtifact = webauthn.artifacts.artifacts.find((item) => item.name.startsWith("external-webauthn-qualification-"));
  const webauthnEvidencePath = path.join(webauthn.root, "webauthn.json");
  const webauthnEvidence = validWebAuthnEvidence("403");
  webauthnEvidence.execution.artifact_sha256 = "e".repeat(64);
  fs.writeFileSync(webauthnEvidencePath, JSON.stringify(webauthnEvidence), { mode: 0o600 });
  const webauthnArchivePath = path.join(webauthn.archives, `${webauthnArtifact.name}.zip`);
  fs.rmSync(webauthnArchivePath);
  execFileSync("zip", ["-q", "-j", webauthnArchivePath, webauthnEvidencePath]);
  webauthnArtifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(webauthnArchivePath)).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...webauthn, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: webauthn.archives }), /WebAuthn qualification/u);

  const wrongArtifact = fixture();
  assert.throws(() => verifyExternalQualificationArtifacts({ ...wrongArtifact, repository, sourceCommit, sourceTree, releaseArtifactSha256: "e".repeat(64), runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: wrongArtifact.archives }), /KMS qualification/u);
});

test("promotion rejects a missing KMS identity attestation and Platform Auth not_run/local/substituted evidence", () => {
  const replaceArchive = (value, job, evidence) => {
    const artifact = value.artifacts.artifacts.find((item) => item.name.startsWith(`external-${job === "platform-auth" ? "platform-auth" : "kms"}-qualification-`));
    const evidencePath = path.join(value.root, `${job}-replacement.json`);
    const archivePath = path.join(value.archives, `${artifact.name}.zip`);
    fs.writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
    fs.rmSync(archivePath);
    execFileSync("zip", ["-q", "-j", archivePath, evidencePath]);
    artifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex")}`;
  };
  const missingAttestation = fixture();
  const kmsEvidencePath = path.join(missingAttestation.root, "kms.json");
  const kmsEvidence = JSON.parse(fs.readFileSync(kmsEvidencePath, "utf8"));
  kmsEvidence.provider_identities = kmsEvidence.provider_identities.map(({ attestation: _attestation, ...identity }) => identity);
  replaceArchive(missingAttestation, "kms", kmsEvidence);
  assert.throws(() => verifyExternalQualificationArtifacts({ ...missingAttestation, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: missingAttestation.archives }), /KMS qualification/u);

  const notRun = fixture();
  const notRunEvidence = JSON.parse(fs.readFileSync(path.join(notRun.root, "platform-auth.json"), "utf8"));
  notRunEvidence.status = "not_run";
  notRunEvidence.qualified = false;
  notRunEvidence.reason = "provider_not_configured";
  replaceArchive(notRun, "platform-auth", notRunEvidence);
  assert.throws(() => verifyExternalQualificationArtifacts({ ...notRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: notRun.archives }), /Platform Auth qualification/u);

  const local = fixture();
  const localEvidence = JSON.parse(fs.readFileSync(path.join(local.root, "platform-auth.json"), "utf8"));
  localEvidence.execution.runner_id = "local-runner";
  replaceArchive(local, "platform-auth", localEvidence);
  assert.throws(() => verifyExternalQualificationArtifacts({ ...local, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: local.archives }), /Platform Auth qualification/u);

  const substituted = fixture();
  const substitutedEvidence = JSON.parse(fs.readFileSync(path.join(substituted.root, "platform-auth.json"), "utf8"));
  substitutedEvidence.execution.run_id = "999";
  replaceArchive(substituted, "platform-auth", substitutedEvidence);
  assert.throws(() => verifyExternalQualificationArtifacts({ ...substituted, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: substituted.archives }), /conflicting run_id|qualification job binding/u);
});

test("rechecks PostgreSQL migration head, catalog, and role detail inside the retained child archive", () => {
  for (const [field, expectedError] of [["c3_schema_head", /runtime provenance/u], ["catalog_constraints_validated", /runtime provenance/u], ["role_privileges_and_ownership", /runtime provenance/u]]) {
    const value = fixture();
    const artifact = value.artifacts.artifacts.find((item) => item.name.startsWith("external-postgres-16-qualification-"));
    const evidencePath = path.join(value.root, "postgres-authority-16.json");
    const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    if (field === "c3_schema_head") evidence[field] = 46;
    else evidence.c3_check_statuses[field] = "not_run";
    fs.writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
    const archivePath = path.join(value.archives, `${artifact.name}.zip`);
    fs.rmSync(archivePath);
    execFileSync("zip", ["-q", "-j", archivePath, evidencePath]);
    artifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex")}`;
    assert.throws(() => verifyExternalQualificationArtifacts({ ...value, canonicalRun: value.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: value.archives }), expectedError);
  }
});

test("rechecks the PostgreSQL aggregate's child bundle digest instead of trusting its summary", () => {
  const value = fixture();
  const artifact = value.artifacts.artifacts.find((item) => item.name.startsWith("external-postgres-gate-"));
  const bundlePath = path.join(value.root, "input", "children.bundle");
  fs.writeFileSync(bundlePath, "tampered child bundle\n", { mode: 0o600 });
  execFileSync("zip", ["-q", "-FS", path.join(value.archives, `${artifact.name}.zip`), "postgres-gate.json", "input/children.bundle"], { cwd: value.root });
  artifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(path.join(value.archives, `${artifact.name}.zip`))).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...value, canonicalRun: value.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: value.archives }), /child bundle digest/u);
});

test("provenance output remains canonical when serialized for the retained artifact", () => {
  const value = fixture();
  const result = verifyExternalQualificationArtifacts({ ...value, canonicalRun: value.canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: value.archives });
  assert.deepEqual(JSON.parse(canonicalJson(result)), result);
});

test("rejects duplicate runner identities and substituted child execution bindings", () => {
  const duplicateRunner = fixture();
  const webauthnArtifact = duplicateRunner.artifacts.artifacts.find((item) => item.name.startsWith("external-webauthn-qualification-"));
  const webauthnPath = path.join(duplicateRunner.root, "webauthn.json");
  const webauthn = JSON.parse(fs.readFileSync(webauthnPath, "utf8"));
  webauthn.execution.runner_id = "protected-kms-runner";
  fs.writeFileSync(webauthnPath, JSON.stringify(webauthn), { mode: 0o600 });
  const webauthnArchive = path.join(duplicateRunner.archives, `${webauthnArtifact.name}.zip`);
  fs.rmSync(webauthnArchive);
  execFileSync("zip", ["-q", "-j", webauthnArchive, webauthnPath]);
  webauthnArtifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(webauthnArchive)).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...duplicateRunner, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: duplicateRunner.archives }), /execution identities are not distinct/u);

  const substituted = fixture();
  const kmsArtifact = substituted.artifacts.artifacts.find((item) => item.name.startsWith("external-kms-qualification-"));
  const kmsPath = path.join(substituted.root, "kms.json");
  const kms = JSON.parse(fs.readFileSync(kmsPath, "utf8"));
  kms.run_id = "999";
  fs.writeFileSync(kmsPath, JSON.stringify(kms), { mode: 0o600 });
  const kmsArchive = path.join(substituted.archives, `${kmsArtifact.name}.zip`);
  fs.rmSync(kmsArchive);
  execFileSync("zip", ["-q", "-j", kmsArchive, kmsPath]);
  kmsArtifact.digest = `sha256:${createHash("sha256").update(fs.readFileSync(kmsArchive)).digest("hex")}`;
  assert.throws(() => verifyExternalQualificationArtifacts({ ...substituted, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory: substituted.archives }), /qualification job binding|source commit|KMS qualification/u);
});
