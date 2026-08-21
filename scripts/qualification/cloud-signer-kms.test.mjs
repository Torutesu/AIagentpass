import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  CLOUD_SIGNER_KMS_QUALIFICATION_KIND,
  CLOUD_SIGNER_KMS_PURPOSES,
  CLOUD_SIGNER_KMS_SCENARIOS,
  canonicalCloudSignerKmsQualificationEvidence,
  normalizeCloudSignerKmsProviderEvidence,
  cloudSignerKmsQualificationSHA256,
  normalizeCloudSignerKmsQualificationEvidence,
  runCloudSignerKmsQualification,
  verifyCloudSignerKmsQualificationEvidence
} from "./cloud-signer-kms.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../../apps/cloud-api/src/signer-purpose-registry.mjs";

const SOURCE_COMMIT = "a".repeat(40);
const SOURCE_TREE = "b".repeat(40);
const DEPLOYMENT_DIGEST = "c".repeat(64);
const RUN_ID = "42";
const JOB_ID = "1001";
const NOW = new Date("2026-08-20T00:00:00.000Z");
const protectedBinding = { sourceCommit: SOURCE_COMMIT, sourceTree: SOURCE_TREE, deploymentDigest: DEPLOYMENT_DIGEST, artifactSha256: "d".repeat(64), runId: RUN_ID, jobId: JOB_ID };
const qualificationEnv = {
  AGENTPASS_KMS_QUALIFICATION_ENABLED: "true",
  AGENTPASS_KMS_QUALIFICATION_EXECUTION: "external",
  AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION: "true",
  AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: "github-actions-kms-qualification",
  AGENTPASS_KMS_QUALIFICATION_CREDENTIAL_MODE: "multi_provider_workload_identity"
};

function binding(name) {
  const expected = SIGNER_PURPOSE_REGISTRY[name];
  const index = CLOUD_SIGNER_KMS_PURPOSES.indexOf(name) + 1;
  return {
    algorithm: "ed25519",
    domain: expected.domain,
    hosted_status: expected.hosted_status,
    key_id: `${name}-kms-key`,
    key_version: String(index),
    name,
    provider: index % 2 === 0 ? "gcp-cloud-kms" : "aws-kms",
    provider_resource_id: index % 2 === 0
      ? `projects/agentpass/locations/global/keyRings/${name}/cryptoKeys/${name}-kms-key/cryptoKeyVersions/${index}`
      : `arn:aws:kms:us-east-1:123456789012:key/${name}-kms-key`,
    public_key_fingerprint: (index.toString(16) + "b").repeat(64).slice(0, 64),
    protocol_version: expected.protocol_version,
    purpose: expected.purpose,
    registry_version: 1,
    signing_version: expected.signing_version,
    version: 1
  };
}

function dependencies(overrides = {}) {
  const calls = { purposes: [], iam: [], scenarios: [], postgres: 0 };
  const handles = new Map(CLOUD_SIGNER_KMS_PURPOSES.map((name) => [name, { secret: "never serialized" }]));
  return {
    calls,
    identityProbe: async () => [
      { account_or_project: "123456789012", authenticated: true, credential_source: "aws_workload_identity", identity: "aws-role-agentpass", identity_fingerprint: "1".repeat(64), provider: "aws-kms", region: "us-east-1" },
      { account_or_project: "agentpass", authenticated: true, credential_source: "gcp_workload_identity", identity: "gcp-service-agentpass", identity_fingerprint: "2".repeat(64), provider: "gcp-cloud-kms", region: "global" }
    ],
    purposeFactory: async ({ name }) => {
      calls.purposes.push(name);
      return { binding: binding(name), handle: handles.get(name) };
    },
    iamProbe: async ({ caller_purpose, key_purpose }) => {
      calls.iam.push([caller_purpose, key_purpose]);
      return { decision: caller_purpose === key_purpose ? "allow" : "deny" };
    },
    scenarioProbe: async ({ expected, scenario }) => {
      calls.scenarios.push([expected.name, scenario]);
      const details = scenario === "provider_contract" ? {
        algorithm: "ed25519", public_key_fingerprint: expected.public_key_fingerprint,
        protocol_version: expected.protocol_version, signature_length: 64, status: "passed"
      } : scenario === "key_version_binding" ? {
        key_id: expected.key_id, key_version: expected.key_version, lifecycle_version: 4, status: "passed"
      } : scenario === "rotation" ? {
        drained: true, new_key_version: expected.key_version, new_signing_allowed: true,
        old_key_version: `${expected.key_version}-old`, old_signing_allowed: false,
        old_verification_allowed: true, status: "passed"
      } : scenario === "disable" ? {
        key_version: expected.key_version, lifecycle_version: 5, provider_called_after_disable: false,
        reserved_after_disable: false, signing_allowed: false, status: "passed", verification_allowed: true
      } : scenario === "non_exportability" ? {
        export_attempted: true, export_rejected: true, exportable: false, private_material_observed: false, status: "passed"
      } : scenario === "lifecycle_fence" ? {
        fenced: true, provider_called_after_fence: true, reserved: true, status: "passed"
      } : scenario === "response_loss_reconciliation" ? {
        blind_retries: 0, lookup_calls: 1, provider_calls: 1, reconciled: true,
        status: "passed", uncertain_transitions: 1
      } : { signature_length: 64, status: "passed", verified: true };
      return {
        schema_version: 1,
        kind: "agentpass-cloud-signer-kms-provider-evidence",
        source_commit: protectedBinding.sourceCommit,
        source_tree: protectedBinding.sourceTree,
        deployment_digest: protectedBinding.deploymentDigest,
        artifact_sha256: protectedBinding.artifactSha256,
        run_id: protectedBinding.runId,
        job_id: protectedBinding.jobId,
        purpose: expected.purpose,
        key_id: expected.key_id,
        key_version: expected.key_version,
        scenario,
        status: details.status,
        details
      };
    },
    postgresProbe: async () => {
      calls.postgres += 1;
      return { status: "passed", instances: [
        { instance_digest: "1".repeat(64), name: "primary", status: "passed" },
        { instance_digest: "2".repeat(64), name: "secondary", status: "passed" }
      ], resilience: {
        blind_retries: 0, failover_recovered: true, response_loss_reconciled: true,
        restart_recovered: true, single_commit: true, status: "passed", two_instance: true,
        uncertain_state_durable: true
      } };
    },
    ...overrides
  };
}

test("is not_run and fail-closed when real KMS qualification is not explicitly armed", async () => {
  let calls = 0;
  const report = await runCloudSignerKmsQualification({
    env: {},
    now: () => NOW,
    purposeFactory: async () => { calls += 1; },
    iamProbe: async () => ({}),
    scenarioProbe: async () => ({}),
    postgresProbe: async () => ({})
  });
  assert.deepEqual(report, {
    schema_version: 2, kind: CLOUD_SIGNER_KMS_QUALIFICATION_KIND, status: "not_run", qualified: false,
    reason: "provider_not_configured", started_at: NOW.toISOString(), completed_at: NOW.toISOString()
  });
  assert.equal(calls, 0);
  assert.deepEqual(verifyCloudSignerKmsQualificationEvidence(canonicalJson(report)), {
    status: "not_run", qualified: false, reason: "provider_not_configured", evidence_sha256: cloudSignerKmsQualificationSHA256(report)
  });
});

test("executes exactly the complete typed matrix without serializing provider handles", async () => {
  const fixture = dependencies();
  const report = await runCloudSignerKmsQualification({
    env: qualificationEnv,
    now: () => NOW,
    ...protectedBinding,
    ...fixture
  });
  assert.equal(report.status, "passed");
  assert.equal(report.qualified, true);
  assert.equal(fixture.calls.purposes.length, 8);
  assert.equal(fixture.calls.iam.length, 64);
  assert.equal(fixture.calls.scenarios.length, 64);
  assert.equal(fixture.calls.postgres, 1);
  assert.equal(JSON.stringify(report).includes("never serialized"), false);
  assert.equal(JSON.stringify(report).includes("secret"), false);
  assert.deepEqual(verifyCloudSignerKmsQualificationEvidence(Buffer.from(canonicalJson(report)), { expectedSourceCommit: SOURCE_COMMIT }), {
    status: "passed", qualified: true, evidence_sha256: cloudSignerKmsQualificationSHA256(report), source_commit: SOURCE_COMMIT,
    source_tree: protectedBinding.sourceTree, deployment_digest: protectedBinding.deploymentDigest, artifact_sha256: protectedBinding.artifactSha256,
    run_id: protectedBinding.runId, job_id: protectedBinding.jobId
  });
});

test("passes one immutable source/artifact/run binding to every provider probe", async () => {
  const fixture = dependencies();
  const seen = [];
  for (const name of ["identityProbe", "purposeFactory", "iamProbe", "scenarioProbe", "postgresProbe"]) {
    const original = fixture[name];
    fixture[name] = async (input = {}) => {
      seen.push({ name, binding: input.binding });
      return original(input);
    };
  }
  const report = await runCloudSignerKmsQualification({
    env: qualificationEnv,
    now: () => NOW,
    ...protectedBinding,
    ...fixture
  });
  assert.equal(report.status, "passed");
  assert.ok(seen.length > 0);
  const expected = {
    source_commit: SOURCE_COMMIT,
    source_tree: SOURCE_TREE,
    deployment_digest: DEPLOYMENT_DIGEST,
    artifact_sha256: protectedBinding.artifactSha256,
    run_id: RUN_ID,
    job_id: JOB_ID
  };
  for (const entry of seen) {
    assert.deepEqual(entry.binding, expected, entry.name);
    assert.equal(Object.isFrozen(entry.binding), true, entry.name);
  }
});

test("does not qualify an authenticated AWS identity for a different KMS account", async () => {
  const base = dependencies();
  const report = await runCloudSignerKmsQualification({
    env: qualificationEnv,
    now: () => NOW,
    ...protectedBinding,
    ...base,
    identityProbe: async () => [
      { account_or_project: "999999999999", authenticated: true, credential_source: "aws_workload_identity", identity: "aws-role-agentpass", identity_fingerprint: "1".repeat(64), provider: "aws-kms", region: "us-east-1" },
      { account_or_project: "agentpass", authenticated: true, credential_source: "gcp_workload_identity", identity: "gcp-service-agentpass", identity_fingerprint: "2".repeat(64), provider: "gcp-cloud-kms", region: "global" }
    ]
  });
  assert.equal(report.status, "failed");
  assert.equal(report.qualified, false);
  assert.equal(report.reason, "invalid_provider_output");
});

test("rejects IAM substitution, missing scenarios, response-loss retries, raw fields, getters, and cycles", async () => {
  const fixture = dependencies({
    iamProbe: async ({ caller_purpose, key_purpose }) => ({ decision: caller_purpose === key_purpose ? "deny" : "deny" })
  });
  const iamMismatch = await runCloudSignerKmsQualification({
    env: qualificationEnv, now: () => NOW, ...protectedBinding, ...fixture
  });
  assert.equal(iamMismatch.status, "failed");
  assert.equal(iamMismatch.reason, "iam_mismatch");
  assert.equal(JSON.stringify(iamMismatch).includes("secret"), false);

  const good = await runCloudSignerKmsQualification({
    env: qualificationEnv, now: () => NOW, ...protectedBinding, ...dependencies()
  });
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence({
    ...good,
    iam_matrix: good.iam_matrix.slice(0, -1)
  }));
  const responseLoss = structuredClone(good);
  const responseScenario = responseLoss.scenarios.find((item) => item.scenario === "response_loss_reconciliation");
  responseScenario.evidence.details.blind_retries = 1;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(responseLoss));

  for (const scenario of ["rotation", "disable"]) {
    const missing = structuredClone(good);
    const item = missing.scenarios.find((candidate) => candidate.scenario === scenario);
    delete item.evidence.details[scenario === "rotation" ? "old_verification_allowed" : "signing_allowed"];
    assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(missing));
  }
  const rotation = structuredClone(good);
  rotation.scenarios.find((item) => item.scenario === "rotation").evidence.details.old_signing_allowed = true;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(rotation));
  const disable = structuredClone(good);
  disable.scenarios.find((item) => item.scenario === "disable").evidence.details.provider_called_after_disable = true;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(disable));
  const resilience = structuredClone(good);
  resilience.postgres.resilience.failover_recovered = false;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(resilience));

  for (const field of ["source_tree", "deployment_digest", "artifact_sha256", "run_id", "job_id"]) {
    const substituted = structuredClone(good);
    substituted.scenarios[0].evidence[field] = field === "source_tree" ? "d".repeat(40)
      : field === "run_id" || field === "job_id" ? "43" : "e".repeat(64);
    assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(substituted), field);
  }
  const keyVersionSubstitution = structuredClone(good);
  keyVersionSubstitution.scenarios[0].evidence.key_version = "9";
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(keyVersionSubstitution));
  const gcpBindingIndex = good.purpose_bindings.findIndex((item) => item.provider === "gcp-cloud-kms");
  const resourceVersionSubstitution = structuredClone(good);
  resourceVersionSubstitution.purpose_bindings[gcpBindingIndex].provider_resource_id =
    resourceVersionSubstitution.purpose_bindings[gcpBindingIndex].provider_resource_id.replace(/cryptoKeyVersions\/\d+$/u, "cryptoKeyVersions/9");
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(resourceVersionSubstitution));
  const exportNotAttempted = structuredClone(good);
  delete exportNotAttempted.scenarios.find((item) => item.scenario === "non_exportability").evidence.details.export_attempted;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(exportNotAttempted));

  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence({ ...good, leaked_provider_output: "secret" }));
  const getter = structuredClone(good);
  Object.defineProperty(getter, "source_commit", { enumerable: true, get() { throw new Error("secret getter"); } });
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(getter));
  const cyclic = structuredClone(good);
  cyclic.scenarios[0].evidence.details.cycle = cyclic;
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence(cyclic));
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence({
    ...good,
    status: "failed",
    qualified: false,
    reason: "incomplete_run",
    purpose_bindings: [],
    iam_matrix: [],
    scenarios: [],
    postgres: { status: "failed", instances: [], leaked_provider_output: "secret" }
  }));
  assert.deepEqual(CLOUD_SIGNER_KMS_SCENARIOS.length, 8);
});

test("provider evidence envelope is typed, source-bound, and rejects raw provider fields", async () => {
  const fixture = dependencies();
  const report = await runCloudSignerKmsQualification({ env: qualificationEnv, now: () => NOW, ...protectedBinding, ...fixture });
  const item = report.scenarios[0];
  assert.deepEqual(Object.keys(item.evidence).sort(), [
    "artifact_sha256", "deployment_digest", "details", "job_id", "key_id", "key_version", "kind",
    "purpose", "run_id", "scenario", "schema_version", "source_commit", "source_tree", "status"
  ]);
  assert.throws(() => normalizeCloudSignerKmsProviderEvidence({ ...item.evidence, raw_provider_output: "secret" }, {
    binding: report.purpose_bindings[0],
    scenario: item.scenario,
    qualificationBinding: {
      source_commit: SOURCE_COMMIT,
      source_tree: SOURCE_TREE,
      deployment_digest: DEPLOYMENT_DIGEST,
      artifact_sha256: protectedBinding.artifactSha256,
      run_id: RUN_ID,
      job_id: JOB_ID
    }
  }));
});

test("does not claim qualification when a probe fails or a source binding is invalid", async () => {
  const base = dependencies();
  const failed = await runCloudSignerKmsQualification({
    env: qualificationEnv, now: () => NOW, ...protectedBinding,
    ...base,
    scenarioProbe: async ({ scenario, ...input }) => {
      if (scenario === "response_loss_reconciliation") throw Object.assign(new Error("provider secret"), { code: "reconciliation_uncertain" });
      return base.scenarioProbe({ scenario, ...input });
    }
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.qualified, false);
  assert.equal(failed.reason, "reconciliation_uncertain");
  assert.equal(JSON.stringify(failed).includes("provider secret"), false);
  assert.deepEqual(verifyCloudSignerKmsQualificationEvidence(failed, { expectedSourceCommit: SOURCE_COMMIT }), {
    status: "failed", qualified: false, evidence_sha256: cloudSignerKmsQualificationSHA256(failed), source_commit: SOURCE_COMMIT,
    source_tree: protectedBinding.sourceTree, deployment_digest: protectedBinding.deploymentDigest, artifact_sha256: protectedBinding.artifactSha256,
    run_id: protectedBinding.runId, job_id: JOB_ID
  });

  const notRun = await runCloudSignerKmsQualification({ env: qualificationEnv, now: () => NOW });
  assert.equal(notRun.status, "not_run");
  assert.equal(notRun.qualified, false);
});

test("emits canonical protected evidence and rejects binding substitutions", async () => {
  const report = await runCloudSignerKmsQualification({ env: qualificationEnv, now: () => NOW, ...protectedBinding, ...dependencies() });
  const bytes = canonicalCloudSignerKmsQualificationEvidence(report);
  assert.equal(bytes, canonicalJson(report));
  assert.throws(() => verifyCloudSignerKmsQualificationEvidence({ ...report, source_tree: "d".repeat(40) }, { expectedSourceCommit: SOURCE_COMMIT, expectedSourceTree: protectedBinding.sourceTree }));
  assert.throws(() => verifyCloudSignerKmsQualificationEvidence({ ...report, artifact_sha256: "e".repeat(64) }, { expectedArtifactSha256: protectedBinding.artifactSha256 }));
  assert.throws(() => verifyCloudSignerKmsQualificationEvidence({ ...report, run_id: "43" }, { expectedSourceCommit: SOURCE_COMMIT, expectedRunId: protectedBinding.runId }));
  assert.throws(() => normalizeCloudSignerKmsQualificationEvidence({ ...report, deployment_digest: "not-a-digest" }));
});

test("preserves the artifact binding on failed evidence and verifies it independently", async () => {
  const base = dependencies();
  const report = await runCloudSignerKmsQualification({
    env: qualificationEnv,
    now: () => NOW,
    ...protectedBinding,
    ...base,
    scenarioProbe: async ({ scenario, ...input }) => {
      if (scenario === "canary_sign_verify") throw Object.assign(new Error("provider output"), { code: "canary_failed" });
      return base.scenarioProbe({ scenario, ...input });
    }
  });
  assert.equal(report.status, "failed");
  assert.equal(report.reason, "canary_failed");
  assert.equal(report.artifact_sha256, protectedBinding.artifactSha256);
  assert.deepEqual(verifyCloudSignerKmsQualificationEvidence(report, {
    expectedSourceCommit: SOURCE_COMMIT,
    expectedSourceTree: SOURCE_TREE,
    expectedDeploymentDigest: DEPLOYMENT_DIGEST,
    expectedArtifactSha256: protectedBinding.artifactSha256,
    expectedRunId: RUN_ID,
    expectedJobId: JOB_ID
  }).artifact_sha256, protectedBinding.artifactSha256);
  assert.throws(() => verifyCloudSignerKmsQualificationEvidence(report, { expectedArtifactSha256: "e".repeat(64) }));
});
